# 2ping - A bi-directional ping utility
# Copyright (C) 2010-2020 Ryan Finnie
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

import errno
import logging
import math
import selectors
import signal
import socket
import sys
import time

try:
    import dns.resolver as dns_resolver
except ImportError as e:
    dns_resolver = e

try:
    import netifaces
except ImportError as e:
    netifaces = e

try:
    import systemd.daemon as systemd_daemon
except ImportError as e:
    systemd_daemon = e

from . import __version__, packets
from .args import parse_args
from .utils import (
    _,
    _pl,
    fuzz_packet,
    div0,
    nunpack,
    platform_info,
    random,
    random_is_systemrandom,
    stats_time,
)


version_string = "2ping {} - {}".format(__version__, platform_info())
clock = time.perf_counter


class SocketClass:
    def __init__(self, sock):
        self.sock = sock
        self.address = sock.getsockname()
        if not self.address:
            self.address = None

        # Functional tags applied to the SocketClass
        self.tags = []
        # Used during client mode for the host tuple to send UDP packets to.
        self.client_host = None
        # (family, type, proto, canonname, sockaddr) of the bound socket
        self.bind_addrinfo = None
        # Whether the sock has been closed
        self.closed = False

        # Dict of PeerState instances, indexed by peer tuple
        self.peer_states = {}

        # Statistics
        self.pings_transmitted = 0
        self.pings_received = 0
        self.packets_transmitted = 0
        self.packets_received = 0
        self.lost_outbound = 0
        self.lost_inbound = 0
        self.errors_received = 0
        self.rtt_total = 0
        self.rtt_total_sq = 0
        self.rtt_count = 0
        self.rtt_min = 0
        self.rtt_max = 0
        self.rtt_ewma = 0

        self.next_send = 0

        self.shutdown_time = 0
        self.session = bytes([random.randint(0, 255) for x in range(8)])

    def __repr__(self):
        attrs = ["fd {}".format(self.fileno())]
        if self.bind_addrinfo:
            attrs.append("bind {}".format(self.bind_addrinfo))
        if self.client_host:
            attrs.append("client {}".format(self.client_host))
        if self.tags:
            attrs.append("tags {}".format(self.tags))
        if self.closed:
            attrs.append("closed")
        return "<SocketClass: {}>".format(", ".join(attrs))

    def fileno(self):
        return self.sock.fileno()


class PeerState:
    def __init__(self, peer_tuple, sock_class):
        self.peer_tuple = peer_tuple
        self.sock_class = sock_class

        # In-flight outbound messages.  Added in the following conditions:
        #   * Outbound packet with OpcodeReplyRequested sent.
        # Removed in following conditions:
        #   * Inbound packet with OpcodeInReplyTo set to it.
        #   * Inbound packet with it in OpcodeInvestigationSeen or OpcodeInvestigationUnseen.
        #   * Cleanup after 10 minutes.
        # If it remains for more than <10> seconds, it it sent as part of
        # OpcodeInvestigate with the next outbound packet with OpcodeReplyRequested set.
        self.sent_messages = {}
        # Seen inbound messages.  Added in the following conditions:
        #   * Inbound packet with OpcodeReplyRequested set.
        # Referenced in the following conditions:
        #   * Inbound packet with it in OpcodeInvestigate.
        # Removed in the following conditions:
        #   * Inbound packet with it in OpcodeCourtesyExpiration.
        #   * Cleanup after 10 minutes.
        self.seen_messages = {}
        # Courtesy messages waiting to be sent.  Added in the following conditions:
        #   * Inbound packet with OpcodeInReplyTo set.
        # Removed in the following conditions:
        #   * Outbound packet where there is room to send it as part of OpcodeCourtesyExpiration.
        #   * Cleanup after 2 minutes.
        self.courtesy_messages = {}
        # Current position of a peer tuple's incrementing ping integer.
        self.ping_position = 0
        # Current encrypted session ID
        self.encrypted_session_id = None
        # Seen encrypted session IVs
        self.encrypted_session_ivs = {}
        # Last time a peer was sent to or received from
        self.last_seen = clock()


class TwoPing:
    def __init__(self, args):
        now = clock()
        self.args = args
        self.time_start = now
        self.fake_time_epoch = random.random() * (2 ** 32)
        self.fake_time_generation = random.randint(0, 65535)
        self.isatty = sys.stdout.isatty()

        self.logger = logging.getLogger()
        self.logger.setLevel(logging.DEBUG)

        self.sock_classes = []
        self.poller = selectors.DefaultSelector()

        # Scheduled events
        self.next_cleanup = now + 60.0
        self.next_stats = 0
        if self.args.stats:
            self.next_stats = now + self.args.stats

        self.old_age_interval = 60.0
        # On Windows, KeyboardInterrupt during select() will not be trapped
        # until a socket event or timeout, so we should set the timeout to
        # a short value.
        if sys.platform.startswith(("win32", "cygwin")):
            self.old_age_interval = 1.0

        # Test for IPv6 functionality.
        self.has_ipv6 = True
        if not socket.has_ipv6:
            self.has_ipv6 = False
        else:
            # BSD jails seem to have has_ipv6 = True, but will throw
            # "Protocol not supported" on bind.  Test for this.
            try:
                socket.socket(socket.AF_INET6, socket.SOCK_DGRAM).close()
            except socket.error as e:
                if e.errno == errno.EPROTONOSUPPORT:
                    self.has_ipv6 = False
                else:
                    raise

        self.is_reload = False

    def print_out(self, *args, **kwargs):
        print(*args, **kwargs)

    def tty_out(self, *args, **kwargs):
        if not self.isatty:
            return
        self.print_out(*args, **kwargs)

    @property
    def sock_classes_open(self):
        return [sock_class for sock_class in self.sock_classes if not sock_class.closed]

    @property
    def sock_classes_active(self):
        now = clock()
        return [
            sock_class
            for sock_class in self.sock_classes_open
            if not sock_class.shutdown_time
            or (sock_class.shutdown_time and sock_class.shutdown_time > now)
        ]

    def handle_socket_error(self, e, sock_class, peer_address=None):
        sock = sock_class.sock
        # Errors from the last send() can be trapped via IP_RECVERR (Linux only).
        sock_class.errors_received += 1
        error_string = str(e)
        try:
            MSG_ERRQUEUE = 8192
            (error_data, error_address) = sock.recvfrom(16384, MSG_ERRQUEUE)
            print_address = error_address[0]
        except socket.error:
            if peer_address:
                print_address = peer_address[0]
            else:
                print_address = str(sock_class)
        if self.args.quiet:
            pass
        elif print_address:
            self.logger.error("{}: {}".format(print_address, error_string))
        else:
            self.logger.error(error_string)

    def process_incoming_packet(self, sock_class):
        sock = sock_class.sock
        recvfrom = self.sock_recvfrom(sock_class)
        time_begin = clock()
        if recvfrom is None:
            # Error handled, simulated packet loss, etc
            return
        data, peer_address = recvfrom
        if peer_address:
            print_address = peer_address[0]
        else:
            print_address = str(sock_class)
        socket_address = sock_class.address
        self.logger.debug("Socket: {}, peer: {}".format(sock_class, peer_address))

        # Per-packet options.
        sock_class.packets_received += 1
        calculated_rtt = None

        peer_tuple = (socket_address, peer_address, sock.type)

        # Preload state tables if the client has not been seen (or has been cleaned).
        if peer_tuple not in sock_class.peer_states:
            sock_class.peer_states[peer_tuple] = PeerState(peer_tuple, sock_class)
        peer_state = sock_class.peer_states[peer_tuple]
        peer_state.last_seen = time_begin

        # Load/parse the packet.
        packet_in = packets.Packet()
        packet_in.load(data)
        if self.args.verbose:
            self.logger.info("RECV: {}".format(packet_in))

        # Decrypt packet if needed.
        if self.args.encrypt:
            if packets.OpcodeEncrypted.id not in packet_in.opcodes:
                sock_class.errors_received += 1
                self.logger.error(
                    _("Encryption required but not provided by {address}").format(
                        address=print_address
                    )
                )
                return
            if (
                packet_in.opcodes[packets.OpcodeEncrypted.id].method_index
                != self.args.encrypt_method_index
            ):
                sock_class.errors_received += 1
                self.logger.error(
                    _(
                        "Encryption method mismatch from {address} (expected {expected}, got {got})"
                    ).format(
                        address=print_address,
                        expected=self.args.encrypt_method_index,
                        got=packet_in.opcodes[packets.OpcodeEncrypted.id].method_index,
                    )
                )
                return
            data = packet_in.opcodes[packets.OpcodeEncrypted.id].decrypt(
                self.args.encrypt.encode("UTF-8")
            )
            encrypted_packet_in = packet_in
            packet_in = packets.Packet()
            packet_in.load(data)
            if peer_state.encrypted_session_id is None:
                peer_state.encrypted_session_id = encrypted_packet_in.opcodes[
                    packets.OpcodeEncrypted.id
                ].session
            if (
                encrypted_packet_in.opcodes[packets.OpcodeEncrypted.id].session
                != peer_state.encrypted_session_id
            ):
                sock_class.errors_received += 1
                self.logger.error(
                    _(
                        "Encryption session mismatch from {address} (expected {expected}, got {got})"
                    ).format(
                        address=print_address,
                        expected=peer_state.encrypted_session_id,
                        got=encrypted_packet_in.opcodes[
                            packets.OpcodeEncrypted.id
                        ].session,
                    )
                )
                return
            if (
                encrypted_packet_in.opcodes[packets.OpcodeEncrypted.id].iv
                in peer_state.encrypted_session_ivs
            ):
                sock_class.errors_received += 1
                self.logger.error(
                    _("Repeated IV {iv} from {address}, discarding").format(
                        iv=encrypted_packet_in.opcodes[packets.OpcodeEncrypted.id].iv,
                        address=print_address,
                    )
                )
                return
            peer_state.encrypted_session_ivs[
                encrypted_packet_in.opcodes[packets.OpcodeEncrypted.id].iv
            ] = (time_begin,)
            if self.args.verbose:
                self.logger.info("DECR: {}".format(packet_in))

        # Verify HMAC if required.
        if self.args.auth:
            if packets.OpcodeHMAC.id not in packet_in.opcodes:
                sock_class.errors_received += 1
                self.logger.error(
                    _("Auth required but not provided by {address}").format(
                        address=print_address
                    )
                )
                return
            if (
                packet_in.opcodes[packets.OpcodeHMAC.id].digest_index
                != self.args.auth_digest_index
            ):
                sock_class.errors_received += 1
                self.logger.error(
                    _(
                        "Auth digest type mismatch from {address} (expected {expected}, got {got})"
                    ).format(
                        address=print_address,
                        expected=self.args.auth_digest_index,
                        got=packet_in.opcodes[packets.OpcodeHMAC.id].digest_index,
                    )
                )
                return
            (test_begin, test_length) = packet_in.opcode_data_positions[
                packets.OpcodeHMAC.id
            ]
            test_begin += 2
            test_length -= 2
            packet_in.opcodes[packets.OpcodeHMAC.id].key = self.args.auth.encode(
                "UTF-8"
            )
            test_data = bytearray(data)
            test_data[2:4] = b"\x00\x00"
            test_data[test_begin : (test_begin + test_length)] = bytes(test_length)
            test_hash = packet_in.opcodes[packets.OpcodeHMAC.id].hash
            test_hash_calculated = packet_in.calculate_hash(
                packet_in.opcodes[packets.OpcodeHMAC.id], test_data
            )
            if test_hash_calculated != test_hash:
                sock_class.errors_received += 1
                self.logger.error(
                    _(
                        "Auth hash failed from {address} (expected {expected}, got {got})"
                    ).format(
                        address=print_address,
                        expected="".join(
                            "{hex:02x}".format(hex=x) for x in test_hash_calculated
                        ),
                        got="".join("{hex:02x}".format(hex=x) for x in test_hash),
                    )
                )
                return

        # If this is in reply to one of our sent packets, it's a ping reply, so handle it specially.
        if packets.OpcodeInReplyTo.id in packet_in.opcodes:
            replied_message_id = packet_in.opcodes[
                packets.OpcodeInReplyTo.id
            ].message_id
            replied_message_id_int = nunpack(replied_message_id)
            if replied_message_id_int in peer_state.sent_messages:
                (sent_time, _unused, ping_position) = peer_state.sent_messages[
                    replied_message_id_int
                ]
                del peer_state.sent_messages[replied_message_id_int]

                calculated_rtt = (time_begin - sent_time) * 1000
                if (
                    self.args.subtract_peer_host_latency
                    and packets.OpcodeHostLatency.id in packet_in.opcodes
                ):
                    calculated_rtt -= (
                        packet_in.opcodes[packets.OpcodeHostLatency.id].delay_us
                        / 1000.0
                    )
                # Peer host latency could be wildly innacurate; guard against negative RTT.
                if calculated_rtt < 0:
                    calculated_rtt = 0

                sock_class.pings_received += 1
                self.update_rtts(sock_class, calculated_rtt)
                if self.args.quiet or self.args.flood:
                    pass
                else:
                    if self.args.audible:
                        self.tty_out("\x07", end="", flush=True)
                    if packets.OpcodeRTTEnclosed.id in packet_in.opcodes:
                        self.logger.info(
                            _(
                                (
                                    "{bytes} bytes from {address}: ping_seq={seq} time={ms:0.03f} ms "
                                    "peertime={peerms:0.03f} ms"
                                )
                            ).format(
                                bytes=len(data),
                                address=print_address,
                                seq=ping_position,
                                ms=calculated_rtt,
                                peerms=(
                                    packet_in.opcodes[
                                        packets.OpcodeRTTEnclosed.id
                                    ].rtt_us
                                    / 1000.0
                                ),
                            )
                        )
                    else:
                        self.logger.info(
                            _(
                                "{bytes} bytes from {address}: ping_seq={seq} time={ms:0.03f} ms"
                            ).format(
                                bytes=len(data),
                                address=print_address,
                                seq=ping_position,
                                ms=calculated_rtt,
                            )
                        )
                    if (packets.OpcodeExtended.id in packet_in.opcodes) and (
                        packets.ExtendedNotice.id
                        in packet_in.opcodes[packets.OpcodeExtended.id].segments
                    ):
                        notice = (
                            packet_in.opcodes[packets.OpcodeExtended.id]
                            .segments[packets.ExtendedNotice.id]
                            .text
                        )
                        self.logger.info(
                            "  " + _("Peer notice: {notice}").format(notice=notice)
                        )
            peer_state.courtesy_messages[replied_message_id_int] = (
                time_begin,
                replied_message_id,
            )

        # Check if any invesitgations results have come back.
        self.check_investigations(peer_state, packet_in)

        # Process courtesy expirations
        if packets.OpcodeCourtesyExpiration.id in packet_in.opcodes:
            for message_id in packet_in.opcodes[
                packets.OpcodeCourtesyExpiration.id
            ].message_ids:
                message_id_int = nunpack(message_id)
                if message_id_int in peer_state.seen_messages:
                    del peer_state.seen_messages[message_id_int]

        # If the peer requested a reply, prepare one.
        if packets.OpcodeReplyRequested.id in packet_in.opcodes:
            # Populate seen_messages.
            peer_state.seen_messages[nunpack(packet_in.message_id)] = (time_begin,)

            # Basic packet configuration.
            packet_out = self.base_packet()
            packet_out.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
            packet_out.opcodes[
                packets.OpcodeInReplyTo.id
            ].message_id = packet_in.message_id

            # If we are matching packet sizes of the peer, adjust the minimum if it falls between min_packet_size
            # and max_packet_size.
            if not self.args.no_match_packet_size:
                data_len = len(data)
                if (data_len <= self.args.max_packet_size) and (
                    data_len >= self.args.min_packet_size
                ):
                    packet_out.min_length = data_len

            # 3-way pings already have the first roundtrip calculated.
            if calculated_rtt is not None:
                packet_out.opcodes[
                    packets.OpcodeRTTEnclosed.id
                ] = packets.OpcodeRTTEnclosed()
                packet_out.opcodes[packets.OpcodeRTTEnclosed.id].rtt_us = int(
                    calculated_rtt * 1000
                )

            # Check for any investigations the peer requested.
            if packets.OpcodeInvestigate.id in packet_in.opcodes:
                for message_id in packet_in.opcodes[
                    packets.OpcodeInvestigate.id
                ].message_ids:
                    if nunpack(message_id) in peer_state.seen_messages:
                        if packets.OpcodeInvestigationSeen.id not in packet_out.opcodes:
                            packet_out.opcodes[
                                packets.OpcodeInvestigationSeen.id
                            ] = packets.OpcodeInvestigationSeen()
                        packet_out.opcodes[
                            packets.OpcodeInvestigationSeen.id
                        ].message_ids.append(message_id)
                    else:
                        if (
                            packets.OpcodeInvestigationUnseen.id
                            not in packet_out.opcodes
                        ):
                            packet_out.opcodes[
                                packets.OpcodeInvestigationUnseen.id
                            ] = packets.OpcodeInvestigationUnseen()
                        packet_out.opcodes[
                            packets.OpcodeInvestigationUnseen.id
                        ].message_ids.append(message_id)

            # If the packet_in is ReplyRequested but not InReplyTo, it is a second leg.  Unless 3-way ping was
            # disabled, request a reply.
            if (packets.OpcodeInReplyTo.id not in packet_in.opcodes) and (
                not self.args.no_3way
            ):
                packet_out.opcodes[
                    packets.OpcodeReplyRequested.id
                ] = packets.OpcodeReplyRequested()

            # Send any investigations we would like to know about.
            self.start_investigations(peer_state, packet_out)

            # Any courtesy expirations we have waiting should be sent.
            if len(peer_state.courtesy_messages) > 0:
                packet_out.opcodes[
                    packets.OpcodeCourtesyExpiration.id
                ] = packets.OpcodeCourtesyExpiration()
                for (
                    courtesy_time,
                    courtesy_message_id,
                ) in peer_state.courtesy_messages.values():
                    packet_out.opcodes[
                        packets.OpcodeCourtesyExpiration.id
                    ].message_ids.append(courtesy_message_id)

            # Calculate the host latency as late as possible.
            packet_out.opcodes[
                packets.OpcodeHostLatency.id
            ] = packets.OpcodeHostLatency()
            time_send = clock()
            packet_out.opcodes[packets.OpcodeHostLatency.id].delay_us = int(
                (time_send - time_begin) * 1000000
            )

            # Dump the packet.
            dump_out = packet_out.dump()

            # If enabled, encrypt the packet and wrap it in a stub packet.
            if self.args.encrypt:
                encrypted_packet = packets.Packet()
                encrypted_packet.opcodes[
                    packets.OpcodeEncrypted.id
                ] = packets.OpcodeEncrypted()
                encrypted_packet.opcodes[
                    packets.OpcodeEncrypted.id
                ].method_index = self.args.encrypt_method_index
                encrypted_packet.opcodes[
                    packets.OpcodeEncrypted.id
                ].session = encrypted_packet_in.opcodes[
                    packets.OpcodeEncrypted.id
                ].session
                encrypted_packet.opcodes[packets.OpcodeEncrypted.id].encrypt(
                    dump_out, self.args.encrypt.encode("UTF-8")
                )
                sock_out = encrypted_packet.dump()
            else:
                sock_out = dump_out

            # Send the packet.
            self.sock_sendto(sock_class, sock_out, peer_address)
            sock_class.packets_transmitted += 1

            # If ReplyRequested is set, we care about its arrival.
            if packets.OpcodeReplyRequested.id in packet_out.opcodes:
                sock_class.pings_transmitted += 1
                peer_state.ping_position += 1
                peer_state.sent_messages[nunpack(packet_out.message_id)] = (
                    time_send,
                    packet_out.message_id,
                    peer_state.ping_position,
                )

            # Examine the sent packet.
            packet_out_examine = packets.Packet()
            packet_out_examine.load(dump_out)

            # Any courtesy expirations which had room in the sent packet should be forgotten.
            if packets.OpcodeCourtesyExpiration.id in packet_out_examine.opcodes:
                for courtesy_message_id in packet_out_examine.opcodes[
                    packets.OpcodeCourtesyExpiration.id
                ].message_ids:
                    courtesy_message_id_int = nunpack(courtesy_message_id)
                    if courtesy_message_id_int in peer_state.courtesy_messages:
                        del peer_state.courtesy_messages[courtesy_message_id_int]

            if self.args.verbose:
                self.logger.info(
                    "SEND{}: {}".format(
                        (" (encrypted)" if self.args.encrypt else ""),
                        packet_out_examine,
                    )
                )

        if sock_class.next_send and (packets.OpcodeInReplyTo.id in packet_in.opcodes):
            self.schedule_next_send(sock_class, reply_received=True)

    def sock_sendto(self, sock_class, data, address=None):
        sock = sock_class.sock
        # Simulate random packet loss.
        if self.args.packet_loss_out and (
            random.random() < (self.args.packet_loss_out / 100.0)
        ):
            return
        # Send the packet.
        try:
            if address:
                sock.sendto(data, address)
            else:
                sock.send(data)
        except socket.error as e:
            self.handle_socket_error(e, sock_class, peer_address=address)

    def sock_recvfrom(self, sock_class):
        sock = sock_class.sock
        try:
            (data, peer_address) = sock.recvfrom(16384)
        except socket.error as e:
            self.handle_socket_error(e, sock_class)
            return

        # Simulate random packet loss.
        if self.args.packet_loss_in and (
            random.random() < (self.args.packet_loss_in / 100.0)
        ):
            return

        # Simulate data corruption
        if self.args.fuzz:
            data = fuzz_packet(data, self.args.fuzz)

        if not peer_address:
            peer_address = None

        return data, peer_address

    def start_investigations(self, peer_state, packet_check):
        if len(peer_state.sent_messages) == 0:
            return
        if packets.OpcodeInvestigate.id in packet_check.opcodes:
            iobj = packet_check.opcodes[packets.OpcodeInvestigate.id]
        else:
            iobj = None
        now = clock()
        for message_id_str in peer_state.sent_messages:
            (sent_time, message_id, _unused) = peer_state.sent_messages[message_id_str]
            if now >= (sent_time + self.args.inquire_wait):
                if iobj is None:
                    iobj = packets.OpcodeInvestigate()
                if message_id not in iobj.message_ids:
                    iobj.message_ids.append(message_id)
        if iobj is not None:
            packet_check.opcodes[packets.OpcodeInvestigate.id] = iobj

    def check_investigations(self, peer_state, packet_check):
        found = {}

        # Inbound/Outbound
        for opcode_id, type_str, type_stat in [
            (packets.OpcodeInvestigationSeen.id, "inbound", "lost_inbound"),
            (packets.OpcodeInvestigationUnseen.id, "outbound", "lost_outbound"),
        ]:
            if opcode_id in packet_check.opcodes:
                for message_id in packet_check.opcodes[opcode_id].message_ids:
                    message_id_int = nunpack(message_id)
                    if message_id_int not in peer_state.sent_messages:
                        continue
                    (_unused, _unused, ping_seq) = peer_state.sent_messages[
                        message_id_int
                    ]
                    if peer_state.peer_tuple[1]:
                        address = peer_state.peer_tuple[1][0]
                    else:
                        address = peer_state.sock_class
                    found[ping_seq] = (type_str, address)
                    del peer_state.sent_messages[message_id_int]
                    setattr(
                        peer_state.sock_class,
                        type_stat,
                        getattr(peer_state.sock_class, type_stat) + 1,
                    )

        if self.args.quiet:
            return
        # Print results
        for ping_seq in sorted(found):
            (loss_type, address) = found[ping_seq]
            if loss_type == "inbound":
                loss_message = "Lost inbound packet from {address}: ping_seq={seq}"
            else:
                loss_message = "Lost outbound packet to {address}: ping_seq={seq}"
            self.logger.error(
                _(loss_message).format(
                    loss_type=loss_type, address=address, seq=ping_seq
                )
            )

    def close_socks(self, sock_classes=None):
        if sock_classes is None:
            sock_classes = self.sock_classes_open
        for sock_class in sock_classes:
            self.logger.debug("Closing socket: {}".format(sock_class))
            self.poller.unregister(sock_class)
            sock_class.sock.close()
            sock_class.closed = True
            sock_class.shutdown_time = clock()
            sock_class.next_send = 0

    def gather_systemd_socks(self):
        # Do nothing if systemd.daemon is not available
        if isinstance(systemd_daemon, ImportError):
            return []

        # If we've done this before, don't re-attempt
        systemd_sock_classes = [
            sock_class
            for sock_class in self.sock_classes
            if "systemd" in sock_class.tags
        ]
        if systemd_sock_classes:
            return systemd_sock_classes

        # Note that listen_fds() defaults to unset_environment=True
        # so we only want to try this once (see above)
        sock_classes = []
        for fd in systemd_daemon.listen_fds():
            for family in (socket.AF_INET6, socket.AF_INET):
                if not systemd_daemon.is_socket_inet(
                    fd, family=family, type=socket.SOCK_DGRAM
                ):
                    continue
                sock = socket.fromfd(fd, family, socket.SOCK_DGRAM)
                sock_class = SocketClass(sock)
                sock_class.tags.append("systemd")
                sock_class.tags.append("listener")
                sock_classes.append(sock_class)
                self.sock_classes.append(sock_class)
                self.poller.register(sock_class, selectors.EVENT_READ)
                self.logger.debug("Opened socket: {}".format(sock_class))

        return sock_classes

    def setup_interface_address(
        self,
        interface_address,
        port=0,
        family=socket.AF_UNSPEC,
        type=socket.SOCK_DGRAM,
        proto=socket.IPPROTO_UDP,
        tags=None,
    ):
        sock_classes = []
        for addrinfo in socket.getaddrinfo(
            interface_address, port, family, type, proto
        ):
            if (
                (addrinfo[0] == socket.AF_INET6)
                and (not self.args.ipv4)
                and self.has_ipv6
            ):
                pass
            elif (addrinfo[0] == socket.AF_INET) and (not self.args.ipv6):
                pass
            else:
                continue

            if tags is not None and "listener" in tags:
                found_existing = False
                for sock_class in self.sock_classes_open:
                    if addrinfo == sock_class.bind_addrinfo:
                        sock_classes.append(sock_class)
                        found_existing = True
                if found_existing:
                    continue

            sock = self.new_socket(addrinfo)
            sock_class = SocketClass(sock)
            if tags is not None:
                for tag in tags:
                    sock_class.tags.append(tag)
            sock_class.bind_addrinfo = addrinfo
            sock_classes.append(sock_class)
            self.sock_classes.append(sock_class)
            self.poller.register(sock_class, selectors.EVENT_READ)
            self.logger.debug("Opened socket: {}".format(sock_class))

        return sock_classes

    def get_system_addresses(self):
        if isinstance(netifaces, ImportError):
            return []

        addrs = set()
        for iface in netifaces.interfaces():
            iface_addrs = netifaces.ifaddresses(iface)
            if (self.args.ipv4 or (not self.args.ipv4 and not self.args.ipv6)) and (
                netifaces.AF_INET in iface_addrs
            ):
                addrs.update(
                    [
                        (f["addr"], netifaces.AF_INET)
                        for f in iface_addrs[netifaces.AF_INET]
                        if "addr" in f
                    ]
                )
            if (
                self.has_ipv6
                and (self.args.ipv6 or (not self.args.ipv4 and not self.args.ipv6))
                and (netifaces.AF_INET6 in iface_addrs)
            ):
                addrs.update(
                    [
                        (f["addr"], netifaces.AF_INET6)
                        for f in iface_addrs[netifaces.AF_INET6]
                        if "addr" in f
                    ]
                )

        return list(addrs)

    def set_high_port(self):
        interface_addresses = self.get_interface_addresses()
        interface_address = interface_addresses[0][0]
        family = interface_addresses[0][1]
        caught_errors = []
        for attempt in range(100):
            port = random.randint(49152, 65535)
            addrinfo = socket.getaddrinfo(
                interface_address, port, family, socket.SOCK_DGRAM, socket.IPPROTO_UDP
            )[0]
            sock = socket.socket(addrinfo[0], addrinfo[1], addrinfo[2])
            try:
                sock.bind(addrinfo[4])
            except socket.error as e:
                caught_errors.append((port, e))
                continue
            sock.close()
            if attempt > 0:
                self.logger.warning(
                    "It took {} attempts to get an unused port: {}".format(
                        attempt + 1, caught_errors
                    )
                )
            self.args.port = str(port)
            return
        raise caught_errors[-1][1]

    def get_interface_addresses(self):
        if self.args.interface_address:
            # Addresses supplied by user
            interface_addresses = [
                (addr, socket.AF_UNSPEC) for addr in self.args.interface_address
            ]
        elif not isinstance(netifaces, ImportError):
            # Addresses provided by netifaces
            interface_addresses = self.get_system_addresses()
        elif self.args.all_interfaces:
            # --all-interfaces is pretty much deprecated; this section is
            # only triggered if it's explicitly passed but netifaces is not
            # installed.
            raise socket.error(
                "All interface addresses not available; please install netifaces"
            )
        else:
            # Last resort
            interface_addresses = [("0.0.0.0", socket.AF_INET)]
            if self.has_ipv6:
                interface_addresses.append(("::", socket.AF_INET6))

        return interface_addresses

    def setup_sockets(self):
        if self.args.port == "-1":
            # Special testing mode
            self.set_high_port()

        if self.args.loopback:
            self.setup_sockets_loopback()
        if self.args.host:
            self.setup_sockets_client()
        if self.args.listen:
            self.gather_systemd_socks()
            self.setup_sockets_listener()

    def setup_sockets_loopback(self):
        # Client socket setup is only done once.
        if [
            sock_class
            for sock_class in self.sock_classes_open
            if "loopback" in sock_class.tags and "client" in sock_class.tags
        ]:
            return

        for i in range(self.args.loopback_pairs):
            sock_client, sock_listener = socket.socketpair(
                socket.AF_UNIX, socket.SOCK_DGRAM
            )
            sock_class_client = SocketClass(sock_client)
            sock_class_client.tags.append("loopback")
            sock_class_client.tags.append("client")
            sock_class_client.next_send = self.time_start
            self.poller.register(sock_class_client, selectors.EVENT_READ)
            self.sock_classes.append(sock_class_client)
            self.logger.debug("Opened socket: {}".format(sock_class_client))

            sock_class_listener = SocketClass(sock_listener)
            sock_class_listener.tags.append("loopback")
            sock_class_listener.tags.append("listener")
            self.poller.register(sock_class_listener, selectors.EVENT_READ)
            self.sock_classes.append(sock_class_listener)
            self.logger.debug("Opened socket: {}".format(sock_class_listener))

    def setup_sockets_listener(self):
        # Do not set up listener sockets if systemd sockets exist.
        if [
            sock_class
            for sock_class in self.sock_classes_open
            if "systemd" in sock_class.tags
        ]:
            return

        interface_addresses = self.get_interface_addresses()
        interface_sock_classes = []
        for interface_address, interface_family in interface_addresses:
            interface_sock_classes += self.setup_interface_address(
                interface_address,
                port=self.args.port,
                family=interface_family,
                tags=["inet", "listener"],
            )

        listener_sock_classes = [
            sock_class
            for sock_class in self.sock_classes_open
            if "inet" in sock_class.tags and "listener" in sock_class.tags
        ]
        to_close = []
        for sock_class in listener_sock_classes:
            if sock_class not in interface_sock_classes:
                to_close.append(sock_class)

        self.close_socks(to_close)

    def get_srv_hosts(self):
        if isinstance(dns_resolver, ImportError):
            raise socket.error(
                "DNS SRV lookups not available; please install dnspython"
            )
        hosts = []
        for lookup in self.args.host:
            lookup_hosts_found = 0
            self.logger.debug("SRV lookup: {}".format(lookup))
            try:
                res = dns_resolver.query(
                    "_{}._udp.{}".format(self.args.srv_service, lookup), "srv"
                )
            except dns_resolver.dns.exception.DNSException as e:
                raise socket.error("{}: {}".format(lookup, e))
            for rdata in res:
                self.logger.debug("SRV result for {}: {}".format(lookup, rdata))
                if (str(rdata.target), rdata.port) in hosts:
                    continue
                hosts.append((str(rdata.target), rdata.port))
                lookup_hosts_found += 1
            if lookup_hosts_found == 0:
                raise socket.error("{}: No SRV results".format(lookup))
        return hosts

    def setup_sockets_client(self):
        # Client socket setup is only done once.
        if [
            sock_class
            for sock_class in self.sock_classes_open
            if "inet" in sock_class.tags and "client" in sock_class.tags
        ]:
            return

        if self.args.srv:
            hosts = self.get_srv_hosts()
        else:
            hosts = [(x, self.args.port) for x in self.args.host]
        for (hostname, port) in hosts:
            if str(port) in ("None", "-1"):
                port = self.args.port
            try:
                self.setup_sockets_client_host(hostname, port)
            except socket.error as e:
                eargs = list(e.args)
                if len(eargs) == 1:
                    eargs[0] = "{}: {}".format(hostname, eargs[0])
                else:
                    eargs[1] = "{}: {}".format(hostname, eargs[1])
                raise socket.error(*eargs)

    def setup_sockets_client_host(self, hostname, port):
        host_info = None
        for addrinfo in socket.getaddrinfo(
            hostname,
            port,
            socket.AF_UNSPEC,
            socket.SOCK_DGRAM,
            socket.IPPROTO_UDP,
            socket.AI_CANONNAME,
        ):
            if (
                (addrinfo[0] == socket.AF_INET6)
                and (not self.args.ipv4)
                and self.has_ipv6
            ):
                host_info = addrinfo
                break
            elif (addrinfo[0] == socket.AF_INET) and (not self.args.ipv6):
                host_info = addrinfo
                break
            else:
                continue
        if host_info is None:
            raise socket.error("Name or service not known")

        if len(self.args.interface_address) == 1:
            interface_address = self.args.interface_address[0]
        elif host_info[0] == socket.AF_INET6:
            interface_address = "::"
        else:
            interface_address = "0.0.0.0"

        for sock_class in self.setup_interface_address(
            interface_address,
            family=host_info[0],
            type=host_info[1],
            proto=host_info[2],
            tags=["inet", "client"],
        ):
            sock_class.client_host = host_info
            sock_class.next_send = self.time_start

    def send_new_ping(self, sock_class, peer_address=None):
        sock = sock_class.sock
        socket_address = sock_class.address
        if not peer_address and sock_class.client_host:
            peer_address = sock_class.client_host[4]
        peer_tuple = (socket_address, peer_address, sock.type)
        if peer_tuple not in sock_class.peer_states:
            sock_class.peer_states[peer_tuple] = PeerState(peer_tuple, sock_class)
        peer_state = sock_class.peer_states[peer_tuple]
        peer_state.last_seen = clock()

        packet_out = self.base_packet()
        packet_out.opcodes[
            packets.OpcodeReplyRequested.id
        ] = packets.OpcodeReplyRequested()
        self.start_investigations(peer_state, packet_out)
        dump_out = packet_out.dump()

        # If enabled, encrypt the packet and wrap it in a stub packet.
        if self.args.encrypt:
            encrypted_packet = packets.Packet()
            encrypted_packet.opcodes[
                packets.OpcodeEncrypted.id
            ] = packets.OpcodeEncrypted()
            encrypted_packet.opcodes[
                packets.OpcodeEncrypted.id
            ].method_index = self.args.encrypt_method_index
            encrypted_packet.opcodes[
                packets.OpcodeEncrypted.id
            ].session = sock_class.session
            encrypted_packet.opcodes[packets.OpcodeEncrypted.id].encrypt(
                dump_out, self.args.encrypt.encode("UTF-8")
            )
            sock_out = encrypted_packet.dump()
        else:
            sock_out = dump_out

        now = clock()
        self.sock_sendto(sock_class, sock_out, peer_address)
        sock_class.packets_transmitted += 1
        sock_class.pings_transmitted += 1
        peer_state.ping_position += 1
        peer_state.sent_messages[nunpack(packet_out.message_id)] = (
            now,
            packet_out.message_id,
            peer_state.ping_position,
        )
        packet_out_examine = packets.Packet()
        packet_out_examine.load(dump_out)
        if self.args.verbose:
            self.logger.info(
                "SEND{}: {}".format(
                    (" (encrypted)" if self.args.encrypt else ""), packet_out_examine
                )
            )

    def update_rtts(self, sock_class, rtt):
        for c in (sock_class,):
            c.rtt_total += rtt
            c.rtt_total_sq += rtt ** 2
            c.rtt_count += 1
            if (rtt < c.rtt_min) or (c.rtt_min == 0):
                c.rtt_min = rtt
            if rtt > c.rtt_max:
                c.rtt_max = rtt
            if c.rtt_ewma == 0:
                c.rtt_ewma = rtt * 8.0
            else:
                c.rtt_ewma += rtt - (c.rtt_ewma / 8.0)

    def sigquit_handler(self, signum, frame):
        self.print_stats(short=True)

    def sighup_handler(self, signum, frame):
        self.logger.debug("Received SIGHUP, scheduling reload")
        self.is_reload = True

    def get_nagios_stats(self):
        sock_class = [
            sock_class
            for sock_class in self.sock_classes
            if "client" in sock_class.tags
        ][0]

        pings_lost = sock_class.pings_transmitted - sock_class.pings_received
        lost_pct = div0(pings_lost, sock_class.pings_transmitted) * 100
        rtt_avg = div0(float(sock_class.rtt_total), sock_class.rtt_count)

        if (lost_pct >= self.args.nagios_crit_loss) or (
            rtt_avg >= self.args.nagios_crit_rta
        ):
            nagios_result = 2
            nagios_result_text = "CRITICAL"
        elif (lost_pct >= self.args.nagios_warn_loss) or (
            rtt_avg >= self.args.nagios_warn_rta
        ):
            nagios_result = 1
            nagios_result_text = "WARNING"
        else:
            nagios_result = 0
            nagios_result_text = "OK"

        nagios_stats_text = _(
            "{result} 2PING - Packet loss = {loss}%, RTA = {avg:0.03f} ms"
        ).format(result=nagios_result_text, loss=int(lost_pct), avg=rtt_avg) + (
            "|rta={avg:0.06f}ms;{avgwarn:0.06f};{avgcrit:0.06f};0.000000 pl={loss}%;{losswarn};{losscrit};0"
        ).format(
            avg=rtt_avg,
            loss=int(lost_pct),
            avgwarn=self.args.nagios_warn_rta,
            avgcrit=self.args.nagios_crit_rta,
            losswarn=int(self.args.nagios_warn_loss),
            losscrit=int(self.args.nagios_crit_loss),
        )
        return nagios_result, nagios_stats_text

    def print_stats(self, short=False):
        time_end = clock()
        for sock_class in self.sock_classes:
            self.print_stats_sock(sock_class, time_end, short=short)

    def print_stats_sock(self, sock_class, time_end, short=False):
        stats_class = sock_class
        time_start = self.time_start
        pings_lost = stats_class.pings_transmitted - stats_class.pings_received
        lost_pct = div0(pings_lost, stats_class.pings_transmitted) * 100
        lost_undetermined = pings_lost - (
            stats_class.lost_outbound + stats_class.lost_inbound
        )
        outbound_pct = (
            div0(stats_class.lost_outbound, stats_class.pings_transmitted) * 100
        )
        inbound_pct = (
            div0(stats_class.lost_inbound, stats_class.pings_transmitted) * 100
        )
        undetermined_pct = div0(lost_undetermined, stats_class.pings_transmitted) * 100
        rtt_avg = div0(float(stats_class.rtt_total), stats_class.rtt_count)
        rtt_ewma = stats_class.rtt_ewma / 8.0
        rtt_mdev = math.sqrt(
            div0(stats_class.rtt_total_sq, stats_class.rtt_count)
            - (div0(stats_class.rtt_total, stats_class.rtt_count) ** 2)
        )
        socket_address = sock_class.address
        if sock_class.client_host:
            if sock_class.client_host[3]:
                hostname = "{} ({})".format(
                    sock_class.client_host[3], sock_class.client_host[4][0]
                )
            else:
                hostname = sock_class.client_host[4][0]
        elif socket_address:
            hostname = socket_address[0]
        else:
            hostname = sock_class
        if short:
            self.logger.info(
                _pl(
                    (
                        "{hostname}: {transmitted}/{received} ping, {loss}% loss "
                        "({outbound}/{inbound}/{undetermined} out/in/undet), min/avg/ewma/max/mdev = "
                        "{min:0.03f}/{avg:0.03f}/{ewma:0.03f}/{max:0.03f}/{mdev:0.03f} ms"
                    ),
                    (
                        "{hostname}: {transmitted}/{received} pings, {loss}% loss "
                        "({outbound}/{inbound}/{undetermined} out/in/undet), min/avg/ewma/max/mdev = "
                        "{min:0.03f}/{avg:0.03f}/{ewma:0.03f}/{max:0.03f}/{mdev:0.03f} ms"
                    ),
                    stats_class.pings_received,
                ).format(
                    hostname=hostname,
                    transmitted=stats_class.pings_transmitted,
                    received=stats_class.pings_received,
                    loss=int(lost_pct),
                    outbound=stats_class.lost_outbound,
                    inbound=stats_class.lost_inbound,
                    undetermined=lost_undetermined,
                    min=stats_class.rtt_min,
                    avg=rtt_avg,
                    ewma=rtt_ewma,
                    max=stats_class.rtt_max,
                    mdev=rtt_mdev,
                )
            )
        else:
            self.logger.info("")
            self.logger.info(
                "--- {} ---".format(
                    _("{hostname} 2ping statistics").format(hostname=hostname)
                )
            )
            self.logger.info(
                _pl(
                    "{transmitted} ping transmitted, {received} received, {loss}% ping loss, time {time}",
                    "{transmitted} pings transmitted, {received} received, {loss}% ping loss, time {time}",
                    stats_class.pings_transmitted,
                ).format(
                    transmitted=stats_class.pings_transmitted,
                    received=stats_class.pings_received,
                    loss=int(lost_pct),
                    time=stats_time(time_end - time_start),
                )
            )
            self.logger.info(
                _pl(
                    (
                        "{outbound} outbound ping loss ({outboundpct}%), {inbound} inbound ({inboundpct}%), "
                        "{undetermined} undetermined ({undeterminedpct}%)"
                    ),
                    (
                        "{outbound} outbound ping losses ({outboundpct}%), {inbound} inbound ({inboundpct}%), "
                        "{undetermined} undetermined ({undeterminedpct}%)"
                    ),
                    stats_class.lost_outbound,
                ).format(
                    outbound=stats_class.lost_outbound,
                    outboundpct=int(outbound_pct),
                    inbound=stats_class.lost_inbound,
                    inboundpct=int(inbound_pct),
                    undetermined=lost_undetermined,
                    undeterminedpct=int(undetermined_pct),
                )
            )
            self.logger.info(
                _(
                    "rtt min/avg/ewma/max/mdev = {min:0.03f}/{avg:0.03f}/{ewma:0.03f}/{max:0.03f}/{mdev:0.03f} ms"
                ).format(
                    min=stats_class.rtt_min,
                    avg=rtt_avg,
                    ewma=rtt_ewma,
                    max=stats_class.rtt_max,
                    mdev=rtt_mdev,
                )
            )
            self.logger.info(
                _pl(
                    "{transmitted} raw packet transmitted, {received} received",
                    "{transmitted} raw packets transmitted, {received} received",
                    stats_class.packets_transmitted,
                ).format(
                    transmitted=stats_class.packets_transmitted,
                    received=stats_class.packets_received,
                )
            )

    def ready(self):
        pass

    def run(self):
        self.logger.debug("Clock value: {:f}".format(clock()))
        self.logger.debug("Poller: {}".format(self.poller))
        if hasattr(signal, "SIGQUIT"):
            signal.signal(signal.SIGQUIT, self.sigquit_handler)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, self.sighup_handler)

        try:
            self.setup_sockets()
        except (socket.error, socket.gaierror) as e:
            if self.args.debug:
                raise
            else:
                self.logger.error(str(e))
                return 1

        for sock_class in self.sock_classes_active:
            if self.args.nagios:
                continue
            socket_address = sock_class.address
            if sock_class.client_host:
                if sock_class.client_host[3]:
                    host_display = "{} ({})".format(
                        sock_class.client_host[3], sock_class.client_host[4][0]
                    )
                else:
                    host_display = "{}".format(sock_class.client_host[4][0])
            elif sock_class.next_send:
                host_display = "{}".format(sock_class)
            elif socket_address:
                host_display = "listener ({})".format(socket_address[0])
            else:
                host_display = "listener ({})".format(sock_class)
            self.logger.info(
                _("2PING {host}: {min} to {max} bytes of data.").format(
                    host=host_display,
                    min=self.args.min_packet_size,
                    max=self.args.max_packet_size,
                )
            )

        self.ready()

        if self.args.preload > 1:
            for sock_class in self.sock_classes_active:
                if not sock_class.next_send:
                    continue
                for i in range(self.args.preload - 1):
                    self.send_new_ping(sock_class)

        try:
            self.loop()
        except KeyboardInterrupt:
            pass

        if self.args.nagios:
            nagios_result, nagios_stats_text = self.get_nagios_stats()
            self.print_out(nagios_stats_text)
        else:
            self.print_stats()
        self.close_socks()
        if self.args.nagios:
            return nagios_result
        else:
            return 0

    def base_packet(self):
        packet_out = packets.Packet()
        if (not self.args.no_send_version) or (self.args.notice):
            packet_out.opcodes[packets.OpcodeExtended.id] = packets.OpcodeExtended()
        if not self.args.no_send_version:
            packet_out.opcodes[packets.OpcodeExtended.id].segments[
                packets.ExtendedVersion.id
            ] = packets.ExtendedVersion()
            packet_out.opcodes[packets.OpcodeExtended.id].segments[
                packets.ExtendedVersion.id
            ].text = version_string
        if self.args.send_time:
            packet_out.opcodes[packets.OpcodeExtended.id].segments[
                packets.ExtendedWallClock.id
            ] = packets.ExtendedWallClock()
            packet_out.opcodes[packets.OpcodeExtended.id].segments[
                packets.ExtendedWallClock.id
            ].time_us = int(time.time() * 1000000)
        if self.args.send_monotonic_clock:
            packet_out.opcodes[packets.OpcodeExtended.id].segments[
                packets.ExtendedMonotonicClock.id
            ] = packets.ExtendedMonotonicClock()
            packet_out.opcodes[packets.OpcodeExtended.id].segments[
                packets.ExtendedMonotonicClock.id
            ].generation = self.fake_time_generation
            packet_out.opcodes[packets.OpcodeExtended.id].segments[
                packets.ExtendedMonotonicClock.id
            ].time_us = int(
                (clock() - self.time_start + self.fake_time_epoch) * 1000000
            )
        if self.args.send_random:
            random_data = bytes(
                [random.randint(0, 255) for x in range(self.args.send_random)]
            )
            packet_out.opcodes[packets.OpcodeExtended.id].segments[
                packets.ExtendedRandom.id
            ] = packets.ExtendedRandom()
            packet_out.opcodes[packets.OpcodeExtended.id].segments[
                packets.ExtendedRandom.id
            ].is_hwrng = False
            packet_out.opcodes[packets.OpcodeExtended.id].segments[
                packets.ExtendedRandom.id
            ].is_os = random_is_systemrandom
            packet_out.opcodes[packets.OpcodeExtended.id].segments[
                packets.ExtendedRandom.id
            ].random_data = random_data
        if self.args.notice:
            packet_out.opcodes[packets.OpcodeExtended.id].segments[
                packets.ExtendedNotice.id
            ] = packets.ExtendedNotice()
            packet_out.opcodes[packets.OpcodeExtended.id].segments[
                packets.ExtendedNotice.id
            ].text = self.args.notice
        if self.args.auth:
            packet_out.opcodes[packets.OpcodeHMAC.id] = packets.OpcodeHMAC()
            packet_out.opcodes[packets.OpcodeHMAC.id].key = self.args.auth.encode(
                "UTF-8"
            )
            packet_out.opcodes[
                packets.OpcodeHMAC.id
            ].digest_index = self.args.auth_digest_index
        packet_out.padding_pattern = self.args.pattern_bytes
        packet_out.min_length = self.args.min_packet_size
        packet_out.max_length = self.args.max_packet_size
        if self.args.encrypt:
            packet_out.align_length = 16
        return packet_out

    def scheduled_cleanup(self):
        self.logger.debug("Cleanup")
        self.setup_sockets()
        for sock_class in self.sock_classes_active:
            self.scheduled_cleanup_sock_class(sock_class)

    def scheduled_cleanup_sock_class(self, sock_class):
        now = clock()
        for peer_tuple in tuple(sock_class.peer_states.keys()):
            peer_state = sock_class.peer_states[peer_tuple]
            if now > peer_state.last_seen + 600.0:
                del sock_class.peer_states[peer_tuple]
                self.logger.debug("Cleanup: Removed {}".format(peer_tuple))
                continue
            for table_name, max_time in (
                ("sent_messages", 600.0),
                ("seen_messages", 600.0),
                ("courtesy_messages", 120.0),
                ("encrypted_session_ivs", 600.0),
            ):
                table = getattr(peer_state, table_name)
                for table_key_name in tuple(table.keys()):
                    if now > (table[table_key_name][0] + max_time):
                        del table[table_key_name]
                        self.logger.debug(
                            "Cleanup: Removed {} {} {}".format(
                                peer_tuple, table_name, table_key_name
                            )
                        )

    def new_socket(self, addrinfo):
        family = addrinfo[0]
        type = addrinfo[1]
        proto = addrinfo[2]
        bind = addrinfo[4]

        sock = socket.socket(family, type, proto)
        try:
            import IN

            sock.setsockopt(socket.IPPROTO_IP, IN.IP_RECVERR, int(True))
        except (ImportError, AttributeError, socket.error):
            pass
        if family == socket.AF_INET6:
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, int(True))
            except (AttributeError, socket.error):
                pass
        sock.bind(bind)
        return sock

    def get_next_wakeup(self):
        now = clock()
        events = [(self.next_cleanup, "cleanup")]
        for sock_class in self.sock_classes_active:
            if sock_class.next_send:
                events.append((sock_class.next_send, "send ({})".format(sock_class)))
            if sock_class.shutdown_time > now:
                events.append(
                    (sock_class.shutdown_time, "shutdown ({})".format(sock_class))
                )
        if self.args.stats:
            events.append((self.next_stats, "stats"))
        if self.args.deadline:
            events.append((self.time_start + self.args.deadline, "deadline"))

        next_wakeup = now + self.old_age_interval
        next_wakeup_reason = "old age"
        for wakeup, reason in events:
            if wakeup < next_wakeup:
                next_wakeup = wakeup
                next_wakeup_reason = reason
        if next_wakeup < now:
            next_wakeup = now
            next_wakeup_reason = "time travel ({})".format(next_wakeup_reason)

        return next_wakeup, next_wakeup_reason

    def schedule_next_send(self, sock_class, reply_received=False):
        now = clock()
        if self.args.adaptive and sock_class.rtt_ewma:
            # Adaptive gets recalculated immediately.
            sock_class.next_send = now + (sock_class.rtt_ewma / 8.0 / 1000.0)
        elif self.args.flood:
            if reply_received:
                # If we're in flood mode and a ping reply was received, send a new ping ASAP.
                sock_class.next_send = now
            else:
                # Send has just happened, give it a short time for reply.
                sock_class.next_send = now + 0.01
        elif not reply_received:
            sock_class.next_send = now + self.args.interval

    def loop_client_send(self):
        now = clock()
        for sock_class in self.sock_classes_active:
            if not sock_class.next_send:
                # Not scheduled to send
                continue
            if now < sock_class.next_send:
                # Not yet time
                continue

            if self.args.count and (sock_class.pings_transmitted >= self.args.count):
                self.logger.debug(
                    "loop_client_send: Setting shutdown time to +{} on {}".format(
                        self.args.interval, sock_class
                    )
                )
                sock_class.shutdown_time = now + self.args.interval
                sock_class.next_send = 0
                continue
            self.send_new_ping(sock_class)
            self.schedule_next_send(sock_class)

    def loop_poller(self, next_wakeup):
        timeout = next_wakeup - clock()
        for key, mask in self.poller.select(timeout=(0 if timeout < 0 else timeout)):
            sock_class = key.fileobj
            try:
                self.process_incoming_packet(sock_class)
            except Exception:
                self.logger.exception(
                    _("Received unexpected exception (please file a bug report)")
                )
                if self.args.debug:
                    raise

            if (
                self.args.count
                and (sock_class.pings_transmitted >= self.args.count)
                and (sock_class.pings_transmitted == sock_class.pings_received)
            ):
                self.logger.debug(
                    "loop_poller: Setting shutdown time to now on {}".format(sock_class)
                )
                sock_class.shutdown_time = clock()
                sock_class.next_send = 0

    def loop(self):
        while True:
            self.loop_client_send()
            next_wakeup, next_wakeup_reason = self.get_next_wakeup()
            self.logger.debug(
                "Next wakeup: {} ({})".format(
                    (next_wakeup - clock()), next_wakeup_reason
                )
            )
            self.loop_poller(next_wakeup)

            now = clock()

            if self.args.stats and now >= self.next_stats:
                self.print_stats(short=True)
                self.next_stats = now + self.args.stats

            if self.args.deadline and now >= (self.time_start + self.args.deadline):
                for sock_class in self.sock_classes_active:
                    self.logger.debug(
                        "loop (deadline): Setting shutdown time to now on {}".format(
                            sock_class
                        )
                    )
                    sock_class.shutdown_time = now
                    sock_class.next_send = 0

            if (
                self.args.count
                and self.args.no_3way
                and len(
                    [
                        sock_class
                        for sock_class in self.sock_classes_active
                        if "client" in sock_class.tags
                    ]
                )
                == 0
            ):
                # Special case for --count and --no-3way on a listener
                for sock_class in [
                    sock_class
                    for sock_class in self.sock_classes_active
                    if "listener" in sock_class.tags
                ]:
                    self.logger.debug(
                        "loop (no_3way): Setting shutdown time to now on {}".format(
                            sock_class
                        )
                    )
                    sock_class.shutdown_time = clock()
                    sock_class.next_send = 0

            if now >= self.next_cleanup:
                self.scheduled_cleanup()
                self.next_cleanup = now + 60.0

            if self.is_reload:
                self.is_reload = False
                self.setup_sockets()

            if len(self.sock_classes_active) == 0:
                return


def main(argv=None):
    if argv is None:
        argv = sys.argv

    args = parse_args(argv)
    t = TwoPing(args)

    if t.args.debug:
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=log_level)

    return t.run()


def module_init():
    if __name__ == "__main__":
        sys.exit(main(sys.argv))


module_init()
