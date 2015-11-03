#!/usr/bin/env python

# 2ping - A bi-directional ping utility
# Copyright (C) 2015 Ryan Finnie
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

from __future__ import print_function, division
import random
import socket
import math
import signal
import sys
import errno
from . import __version__
from . import packets
from . import monotonic_clock
from . import best_poller
from .args import parse_args
from .utils import lazy_div, bytearray_to_int, platform_info

try:
    import dns.resolver
    has_dns = True
except ImportError:
    has_dns = False

version_string = '2ping %s - %s' % (__version__, platform_info())
clock = monotonic_clock.clock


class SocketClass():
    def __init__(self, sock):
        self.sock = sock

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
        #   * Cleanup after 2 minutes.
        self.seen_messages = {}
        # Courtesy messages waiting to be sent.  Added in the following conditions:
        #   * Inbound packet with OpcodeInReplyTo set.
        # Removed in the following conditions:
        #   * Outbound packet where there is room to send it as part of OpcodeCourtesyExpiration.
        #   * Cleanup after 2 minutes.
        self.courtesy_messages = {}
        # Current position of a peer tuple's incrementing ping integer.
        self.ping_positions = {}
        # Used during client mode for the host tuple to send UDP packets to.
        self.client_host = None

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

        self.is_shutdown = False

    def fileno(self):
        return self.sock.fileno()


class TwoPing():
    def __init__(self, args):
        now = clock()
        self.args = args
        self.time_start = now

        self.sock_classes = []
        self.poller = best_poller.best_poller()

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

        # Scheduled events
        self.next_cleanup = now + 60.0
        self.next_stats = 0
        if self.args.stats:
            self.next_stats = now + self.args.stats

        self.old_age_interval = 60.0
        # On Windows, KeyboardInterrupt during select() will not be trapped until a socket event or timeout, so we should set
        # the timeout to a short value.
        if sys.platform.startswith(('win32', 'cygwin')):
            self.old_age_interval = 1.0

        # Test for IPv6 functionality.
        self.has_ipv6 = True
        if not socket.has_ipv6:
            self.has_ipv6 = False
        else:
            # BSD jails seem to have has_ipv6 = True, but will throw "Protocol not supported" on bind.  Test for this.
            try:
                socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            except socket.error as e:
                if e.errno == errno.EPROTONOSUPPORT:
                    self.has_ipv6 = False
                else:
                    raise

    def print_out(self, *args, **kwargs):
        '''Emulate Python 3's complete print() functionality'''
        if 'sep' not in kwargs:
            kwargs['sep'] = ' '
        if 'end' not in kwargs:
            kwargs['end'] = '\n'
        if 'file' not in kwargs:
            kwargs['file'] = sys.stdout
        if 'flush' not in kwargs:
            kwargs['flush'] = False
        kwargs['file'].write(kwargs['sep'].join(args) + kwargs['end'])
        if kwargs['flush']:
            kwargs['file'].flush()

    def print_debug(self, *args, **kwargs):
        if not self.args.debug:
            return
        self.print_out(*args, **kwargs)

    def shutdown(self):
        self.print_stats()
        sys.exit(0)

    def handle_socket_error(self, e, sock_class, peer_address=None):
        sock = sock_class.sock
        # Errors from the last send() can be trapped via IP_RECVERR (Linux only).
        self.errors_received += 1
        sock_class.errors_received += 1
        error_string = str(e)
        try:
            MSG_ERRQUEUE = 8192
            (error_data, error_address) = sock.recvfrom(16384, MSG_ERRQUEUE)
            if self.args.quiet:
                pass
            elif self.args.flood:
                self.print_out('\x08E', end='', flush=True)
            else:
                self.print_out('%s: %s' % (error_address[0], error_string))
        except socket.error:
            if self.args.quiet:
                pass
            elif self.args.flood:
                self.print_out('\x08E', end='', flush=True)
            else:
                if peer_address:
                    self.print_out('%s: %s' % (peer_address[0], error_string))
                else:
                    self.print_out(error_string)

    def process_incoming_packet(self, sock_class):
        sock = sock_class.sock
        try:
            (data, peer_address) = sock.recvfrom(16384)
        except socket.error as e:
            self.handle_socket_error(e, sock_class)
            return
        socket_address = sock.getsockname()
        self.print_debug('Socket address: %s' % repr(socket_address))
        self.print_debug('Peer address: %s' % repr(peer_address))
        data = bytearray(data)

        # Simulate random packet loss.
        if self.args.packet_loss_in and (random.random() < (self.args.packet_loss_in / 100.0)):
            return

        # Per-packet options.
        self.packets_received += 1
        sock_class.packets_received += 1
        calculated_rtt = None

        time_begin = clock()
        peer_tuple = (socket_address, peer_address, sock.type)

        # Preload state tables if the client has not been seen (or has been cleaned).
        if peer_tuple not in sock_class.seen_messages:
            sock_class.seen_messages[peer_tuple] = {}
        if peer_tuple not in sock_class.sent_messages:
            sock_class.sent_messages[peer_tuple] = {}
        if peer_tuple not in sock_class.courtesy_messages:
            sock_class.courtesy_messages[peer_tuple] = {}
        if peer_tuple not in sock_class.ping_positions:
            sock_class.ping_positions[peer_tuple] = 0

        # Load/parse the packet.
        packet_in = packets.Packet()
        packet_in.load(data)
        if self.args.verbose:
            self.print_out('RECV: %s' % repr(packet_in))

        # Verify HMAC if required.
        if self.args.auth:
            if packets.OpcodeHMAC.id not in packet_in.opcodes:
                self.errors_received += 1
                sock_class.errors_received += 1
                self.print_out('Auth required but not provided by %s' % peer_address[0])
                return
            if packet_in.opcodes[packets.OpcodeHMAC.id].digest_index != self.args.auth_digest_index:
                self.errors_received += 1
                sock_class.errors_received += 1
                self.print_out(
                    'Auth digest type mismatch from %s (expected %d, got %d)' % (
                        peer_address[0], self.args.auth_digest_index, packet_in.opcodes[packets.OpcodeHMAC.id].digest_index
                    )
                )
                return
            (test_begin, test_length) = packet_in.opcode_data_positions[packets.OpcodeHMAC.id]
            test_begin += 2
            test_length -= 2
            packet_in.opcodes[packets.OpcodeHMAC.id].key = bytearray(self.args.auth)
            test_data = data
            test_data[2:4] = bytearray(2)
            test_data[test_begin:(test_begin+test_length)] = bytearray(test_length)
            test_hash = packet_in.opcodes[packets.OpcodeHMAC.id].hash
            test_hash_calculated = packet_in.calculate_hash(packet_in.opcodes[packets.OpcodeHMAC.id], test_data)
            if test_hash_calculated != test_hash:
                self.errors_received += 1
                sock_class.errors_received += 1
                self.print_out(
                    'Auth hash failed from %s (expected %s, got %s)' % (
                        peer_address[0],
                        ''.join('{:02x}'.format(x) for x in test_hash_calculated),
                        ''.join('{:02x}'.format(x) for x in test_hash)
                    )
                )
                return

        # Check if any invesitgations results have come back.
        self.check_investigations(sock_class, peer_tuple, packet_in)
        if packets.OpcodeCourtesyExpiration.id in packet_in.opcodes:
            for message_id in packet_in.opcodes[packets.OpcodeCourtesyExpiration.id].message_ids:
                message_id_int = bytearray_to_int(message_id)
                if message_id_int in sock_class.seen_messages[peer_tuple]:
                    del(sock_class.seen_messages[peer_tuple][message_id_int])

        # If this is in reply to one of our sent packets, it's a ping reply, so handle it specially.
        if packets.OpcodeInReplyTo.id in packet_in.opcodes:
            replied_message_id = packet_in.opcodes[packets.OpcodeInReplyTo.id].message_id
            replied_message_id_int = bytearray_to_int(replied_message_id)
            if replied_message_id_int in sock_class.sent_messages[peer_tuple]:
                (sent_time, _, ping_position) = sock_class.sent_messages[peer_tuple][replied_message_id_int]
                del(sock_class.sent_messages[peer_tuple][replied_message_id_int])
                calculated_rtt = (time_begin - sent_time) * 1000
                self.pings_received += 1
                sock_class.pings_received += 1
                self.update_rtts(sock_class, calculated_rtt)
                if self.args.quiet:
                    pass
                elif self.args.flood:
                    self.print_out('\x08', end='', flush=True)
                else:
                    str_peertime = ''
                    if packets.OpcodeRTTEnclosed.id in packet_in.opcodes:
                        str_peertime = ' peertime=%0.03f ms' % (packet_in.opcodes[packets.OpcodeRTTEnclosed.id].rtt_us / 1000.0)
                    str_audible = ''
                    if self.args.audible:
                        str_audible = '\x07'
                    self.print_out(
                        '%d bytes from %s: ping_seq=%d time=%0.03f ms%s%s' % (
                            len(data), peer_tuple[1][0], ping_position, calculated_rtt, str_peertime, str_audible
                        )
                    )
                    if (
                        (packets.OpcodeExtended.id in packet_in.opcodes) and
                        (packets.ExtendedNotice.id in packet_in.opcodes[packets.OpcodeExtended.id].segments)
                    ):
                        notice = str(packet_in.opcodes[packets.OpcodeExtended.id].segments[packets.ExtendedNotice.id].text)
                        self.print_out('  Peer notice: %s' % notice)
            sock_class.courtesy_messages[peer_tuple][replied_message_id_int] = (time_begin, replied_message_id)

        # If the peer requested a reply, prepare one.
        if packets.OpcodeReplyRequested.id in packet_in.opcodes:
            # Populate seen_messages.
            sock_class.seen_messages[peer_tuple][bytearray_to_int(packet_in.message_id)] = time_begin

            # Basic packet configuration.
            packet_out = self.base_packet()
            packet_out.opcodes[packets.OpcodeInReplyTo.id] = packets.OpcodeInReplyTo()
            packet_out.opcodes[packets.OpcodeInReplyTo.id].message_id = packet_in.message_id

            # If we are matching packet sizes of the peer, adjust the minimum if it falls between min_packet_size
            # and max_packet_size.
            if not self.args.no_match_packet_size:
                data_len = len(data)
                if (data_len <= self.args.max_packet_size) and (data_len >= self.args.min_packet_size):
                    packet_out.min_length = data_len

            # 3-way pings already have the first roundtrip calculated.
            if calculated_rtt is not None:
                packet_out.opcodes[packets.OpcodeRTTEnclosed.id] = packets.OpcodeRTTEnclosed()
                packet_out.opcodes[packets.OpcodeRTTEnclosed.id].rtt_us = int(calculated_rtt * 1000)

            # Check for any investigations the peer requested.
            if packets.OpcodeInvestigate.id in packet_in.opcodes:
                for message_id in packet_in.opcodes[packets.OpcodeInvestigate.id].message_ids:
                    if bytearray_to_int(message_id) in sock_class.seen_messages[peer_tuple]:
                        if packets.OpcodeInvestigationSeen.id not in packet_out.opcodes:
                            packet_out.opcodes[packets.OpcodeInvestigationSeen.id] = packets.OpcodeInvestigationSeen()
                        packet_out.opcodes[packets.OpcodeInvestigationSeen.id].message_ids.append(message_id)
                    else:
                        if packets.OpcodeInvestigationUnseen.id not in packet_out.opcodes:
                            packet_out.opcodes[packets.OpcodeInvestigationUnseen.id] = packets.OpcodeInvestigationUnseen()
                        packet_out.opcodes[packets.OpcodeInvestigationUnseen.id].message_ids.append(message_id)

            # If the packet_in is ReplyRequested but not InReplyTo, it is a second leg.  Unless 3-way ping was
            # disabled, request a reply.
            if (packets.OpcodeInReplyTo.id not in packet_in.opcodes) and (not self.args.no_3way):
                packet_out.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()

            # Send any investigations we would like to know about.
            self.start_investigations(sock_class, peer_tuple, packet_out)

            # Any courtesy expirations we have waiting should be sent.
            if len(sock_class.courtesy_messages[peer_tuple]) > 0:
                packet_out.opcodes[packets.OpcodeCourtesyExpiration.id] = packets.OpcodeCourtesyExpiration()
                for (courtesy_time, courtesy_message_id) in sock_class.courtesy_messages[peer_tuple].values():
                    packet_out.opcodes[packets.OpcodeCourtesyExpiration.id].message_ids.append(courtesy_message_id)

            # Calculate the host latency as late as possible.
            packet_out.opcodes[packets.OpcodeHostLatency.id] = packets.OpcodeHostLatency()
            time_send = clock()
            packet_out.opcodes[packets.OpcodeHostLatency.id].delay_us = int((time_send - time_begin) * 1000000)

            # Dump the packet.
            dump_out = packet_out.dump()

            # Send the packet.
            self.sock_sendto(sock_class, dump_out, peer_address)
            self.packets_transmitted += 1
            sock_class.packets_transmitted += 1

            # If ReplyRequested is set, we care about its arrival.
            if packets.OpcodeReplyRequested.id in packet_out.opcodes:
                self.pings_transmitted += 1
                sock_class.pings_transmitted += 1
                sock_class.ping_positions[peer_tuple] += 1
                sock_class.sent_messages[peer_tuple][bytearray_to_int(packet_out.message_id)] = (
                    time_send,
                    packet_out.message_id,
                    sock_class.ping_positions[peer_tuple]
                )

            # Examine the sent packet.
            packet_out_examine = packets.Packet()
            packet_out_examine.load(dump_out)

            # Any courtesy expirations which had room in the sent packet should be forgotten.
            if packets.OpcodeCourtesyExpiration.id in packet_out_examine.opcodes:
                for courtesy_message_id in packet_out_examine.opcodes[packets.OpcodeCourtesyExpiration.id].message_ids:
                    courtesy_message_id_int = bytearray_to_int(courtesy_message_id)
                    if courtesy_message_id_int in sock_class.courtesy_messages[peer_tuple]:
                        del(sock_class.courtesy_messages[peer_tuple][courtesy_message_id_int])

            if self.args.verbose:
                self.print_out('SEND: %s' % repr(packet_out_examine))

        # If we're in flood mode and this is a ping reply, send a new ping ASAP.
        if self.args.flood and (not self.args.listen) and (packets.OpcodeInReplyTo.id in packet_in.opcodes):
            sock_class.next_send = time_begin

    def sock_sendto(self, sock_class, data, address):
        sock = sock_class.sock
        # Simulate random packet loss.
        if self.args.packet_loss_out and (random.random() < (self.args.packet_loss_out / 100.0)):
            return
        # Send the packet.
        try:
            sock.sendto(data, address)
        except socket.error as e:
            self.handle_socket_error(e, sock_class, peer_address=address)

    def start_investigations(self, sock_class, peer_tuple, packet_check):
        if len(sock_class.sent_messages[peer_tuple]) == 0:
            return
        if packets.OpcodeInvestigate.id in packet_check.opcodes:
            iobj = packet_check.opcodes[packets.OpcodeInvestigate.id]
        else:
            iobj = None
        now = clock()
        for message_id_str in sock_class.sent_messages[peer_tuple]:
            (sent_time, message_id, _) = sock_class.sent_messages[peer_tuple][message_id_str]
            if now >= (sent_time + self.args.inquire_wait):
                if iobj is None:
                    iobj = packets.OpcodeInvestigate()
                if message_id not in iobj.message_ids:
                    iobj.message_ids.append(message_id)
        if iobj is not None:
            packet_check.opcodes[packets.OpcodeInvestigate.id] = iobj

    def check_investigations(self, sock_class, peer_tuple, packet_check):
        # Inbound
        if packets.OpcodeInvestigationSeen.id in packet_check.opcodes:
            for message_id in packet_check.opcodes[packets.OpcodeInvestigationSeen.id].message_ids:
                message_id_int = bytearray_to_int(message_id)
                if message_id_int not in sock_class.sent_messages[peer_tuple]:
                    continue
                if self.args.quiet:
                    pass
                elif self.args.flood:
                    self.print_out('\x08<', end='', flush=True)
                else:
                    (_, _, ping_seq) = sock_class.sent_messages[peer_tuple][message_id_int]
                    self.print_out('Lost inbound packet from %s: ping_seq=%d' % (peer_tuple[1][0], ping_seq))
                del(sock_class.sent_messages[peer_tuple][message_id_int])
                self.lost_inbound += 1
                sock_class.lost_inbound += 1
        # Outbound
        if packets.OpcodeInvestigationUnseen.id in packet_check.opcodes:
            for message_id in packet_check.opcodes[packets.OpcodeInvestigationUnseen.id].message_ids:
                message_id_int = bytearray_to_int(message_id)
                if message_id_int not in sock_class.sent_messages[peer_tuple]:
                    continue
                if self.args.quiet:
                    pass
                elif self.args.flood:
                    self.print_out('\x08>', end='', flush=True)
                else:
                    (_, _, ping_seq) = sock_class.sent_messages[peer_tuple][message_id_int]
                    self.print_out('Lost outbound packet to %s: ping_seq=%d' % (peer_tuple[1][0], ping_seq))
                del(sock_class.sent_messages[peer_tuple][message_id_int])
                self.lost_outbound += 1
                sock_class.lost_outbound += 1

    def setup_listener(self):
        bound_addresses = []
        if self.args.interface_address:
            interface_addresses = self.args.interface_address
        else:
            interface_addresses = ['0.0.0.0']
            if self.has_ipv6:
                interface_addresses.append('::')
        for interface_address in interface_addresses:
            for l in socket.getaddrinfo(
                interface_address,
                self.args.port,
                socket.AF_UNSPEC,
                socket.SOCK_DGRAM,
                socket.IPPROTO_UDP
            ):
                if l in bound_addresses:
                    continue
                if (l[0] == socket.AF_INET6) and (not self.args.ipv4) and self.has_ipv6:
                    pass
                elif (l[0] == socket.AF_INET) and (not self.args.ipv6):
                    pass
                else:
                    continue
                sock = self.new_socket(l[0], l[1], l[4])
                sock_class = SocketClass(sock)
                self.sock_classes.append(sock_class)
                self.poller.register(sock_class)
                bound_addresses.append(l)
                self.print_out('2PING listener (%s): %d to %d bytes of data.' % (
                    l[4][0],
                    self.args.min_packet_size,
                    self.args.max_packet_size,
                ))

    def setup_client(self):
        if self.args.srv:
            if not has_dns:
                raise socket.error('DNS SRV lookups not available; please install dnspython')
            hosts = []
            for lookup in self.args.host:
                lookup_hosts_found = 0
                self.print_debug('SRV lookup: %s' % lookup)
                for rdata in dns.resolver.query('_2ping._udp.%s' % lookup, 'srv'):
                    self.print_debug('SRV result for %s: %s' % (
                        lookup,
                        repr(rdata),
                    ))
                    if (str(rdata.target), rdata.port) in hosts:
                        continue
                    hosts.append((str(rdata.target), rdata.port))
                    lookup_hosts_found += 1
                if lookup_hosts_found == 0:
                    raise socket.error('%s: No SRV results' % lookup)
        else:
            hosts = [(x, self.args.port) for x in self.args.host]
        for (hostname, port) in hosts:
            try:
                self.setup_client_host(hostname, port)
            except socket.error as e:
                eargs = list(e.args)
                if len(eargs) == 1:
                    eargs[0] = '%s: %s' % (hostname, eargs[0])
                else:
                    eargs[1] = '%s: %s' % (hostname, eargs[1])
                raise socket.error(*eargs)

    def setup_client_host(self, hostname, port):
        host_info = None
        for l in socket.getaddrinfo(
                hostname,
                port,
                socket.AF_UNSPEC,
                socket.SOCK_DGRAM,
                socket.IPPROTO_UDP,
                socket.AI_CANONNAME,
        ):
            if (l[0] == socket.AF_INET6) and (not self.args.ipv4) and self.has_ipv6:
                host_info = l
                break
            elif (l[0] == socket.AF_INET) and (not self.args.ipv6):
                host_info = l
                break
            else:
                continue
        if host_info is None:
            raise socket.error('Name or service not known')

        bind_info = None
        if self.args.interface_address:
            h = self.args.interface_address[-1]
        else:
            if host_info[0] == socket.AF_INET6:
                h = '::'
            else:
                h = '0.0.0.0'
        for l in socket.getaddrinfo(h, 0, host_info[0], socket.SOCK_DGRAM, socket.IPPROTO_UDP):
            bind_info = l
            break
        if bind_info is None:
            raise socket.error('Cannot find suitable bind for %s' % host_info[4])
        sock = self.new_socket(bind_info[0], bind_info[1], bind_info[4])
        sock_class = SocketClass(sock)
        sock_class.client_host = host_info
        self.sock_classes.append(sock_class)
        self.poller.register(sock_class)
        self.print_out(
            '2PING %s (%s): %d to %d bytes of data.' % (
                host_info[3], host_info[4][0], self.args.min_packet_size, self.args.max_packet_size
            )
        )

    def send_new_ping(self, sock_class, peer_address):
        sock = sock_class.sock
        socket_address = sock.getsockname()
        peer_tuple = (socket_address, peer_address, sock.type)
        if peer_tuple not in sock_class.sent_messages:
            sock_class.sent_messages[peer_tuple] = {}
        if peer_tuple not in sock_class.ping_positions:
            sock_class.ping_positions[peer_tuple] = 0

        packet_out = self.base_packet()
        packet_out.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
        self.start_investigations(sock_class, peer_tuple, packet_out)
        dump_out = packet_out.dump()
        now = clock()
        self.sock_sendto(sock_class, dump_out, peer_address)
        self.packets_transmitted += 1
        sock_class.packets_transmitted += 1
        self.pings_transmitted += 1
        sock_class.pings_transmitted += 1
        sock_class.ping_positions[peer_tuple] += 1
        sock_class.sent_messages[peer_tuple][bytearray_to_int(packet_out.message_id)] = (
            now,
            packet_out.message_id,
            sock_class.ping_positions[peer_tuple]
        )
        packet_out_examine = packets.Packet()
        packet_out_examine.load(dump_out)
        if self.args.quiet:
            pass
        elif self.args.flood:
            self.print_out('.', end='', flush=True)
        if self.args.verbose:
            self.print_out('SEND: %s' % repr(packet_out_examine))

    def update_rtts(self, sock_class, rtt):
        for c in (self, sock_class):
            c.rtt_total += rtt
            c.rtt_total_sq += (rtt ** 2)
            c.rtt_count += 1
            if (rtt < c.rtt_min) or (c.rtt_min == 0):
                c.rtt_min = rtt
            if rtt > c.rtt_max:
                c.rtt_max = rtt
            if c.rtt_ewma == 0:
                c.rtt_ewma = rtt * 8.0
            else:
                c.rtt_ewma += (rtt - (c.rtt_ewma / 8.0))

    def sigquit_handler(self, signum, frame):
        self.print_stats(short=True)

    def print_stats(self, short=False):
        time_end = clock()
        if self.args.listen:
            self.print_stats_sock(time_end, short=short, sock_class=None)
        else:
            for sock_class in self.sock_classes:
                self.print_stats_sock(time_end, short=short, sock_class=sock_class)

    def print_stats_sock(self, time_end, short=False, sock_class=None):
        if sock_class is not None:
            stats_class = sock_class
        else:
            stats_class = self
        time_start = self.time_start
        pings_lost = stats_class.pings_transmitted - stats_class.pings_received
        lost_pct = lazy_div(pings_lost, stats_class.pings_transmitted) * 100
        lost_undetermined = pings_lost - (stats_class.lost_outbound + stats_class.lost_inbound)
        outbound_pct = lazy_div(stats_class.lost_outbound, stats_class.pings_transmitted) * 100
        inbound_pct = lazy_div(stats_class.lost_inbound, stats_class.pings_transmitted) * 100
        undetermined_pct = lazy_div(lost_undetermined, stats_class.pings_transmitted) * 100
        rtt_avg = lazy_div(float(stats_class.rtt_total), stats_class.rtt_count)
        rtt_ewma = stats_class.rtt_ewma / 8.0
        rtt_mdev = math.sqrt(
            lazy_div(stats_class.rtt_total_sq, stats_class.rtt_count) -
            (lazy_div(stats_class.rtt_total, stats_class.rtt_count) ** 2)
        )
        if self.args.listen:
            hostname = 'Listener'
        else:
            hostname = sock_class.client_host[3]
        if short:
            self.print_out(
                '\x0d%s: %d/%d pings, %d%% loss' % (
                    hostname,
                    stats_class.pings_transmitted, stats_class.pings_received, lost_pct,
                ) +
                ' (%d/%d/%d out/in/undet),' % (
                    stats_class.lost_outbound, stats_class.lost_inbound, lost_undetermined,
                ) +
                ' min/avg/ewma/max/mdev = %0.03f/%0.03f/%0.03f/%0.03f/%0.03f ms' % (
                    stats_class.rtt_min, rtt_avg, rtt_ewma, stats_class.rtt_max, rtt_mdev,
                ),
                file=sys.stderr,
            )
        else:
            self.print_out('')
            self.print_out('--- %s 2ping statistics ---' % hostname)
            self.print_out('%d pings transmitted, %d received, %d%% ping loss, time %dms' % (
                stats_class.pings_transmitted,
                stats_class.pings_received,
                lost_pct,
                (time_end - time_start) * 1000,
            ))
            self.print_out('%d outbound ping losses (%d%%), %d inbound (%d%%), %d undetermined (%d%%)' % (
                stats_class.lost_outbound,
                outbound_pct,
                stats_class.lost_inbound,
                inbound_pct,
                lost_undetermined,
                undetermined_pct,
            ))
            self.print_out('rtt min/avg/ewma/max/mdev = %0.03f/%0.03f/%0.03f/%0.03f/%0.03f ms' % (
                stats_class.rtt_min,
                rtt_avg,
                rtt_ewma,
                stats_class.rtt_max,
                rtt_mdev,
            ))
            self.print_out('%d raw packets transmitted, %d received' % (
                stats_class.packets_transmitted, stats_class.packets_received
            ))

    def run(self):
        self.print_debug('Clock: %s, value: %f' % (monotonic_clock.get_clock_info('clock'), clock()))
        self.print_debug('Poller: %s' % self.poller.poller_type)
        if hasattr(signal, 'SIGQUIT'):
            signal.signal(signal.SIGQUIT, self.sigquit_handler)

        try:
            if self.args.listen:
                self.setup_listener()
            else:
                self.setup_client()
        except (socket.error, socket.gaierror) as e:
            self.print_out(str(e))
            return 1

        try:
            self.loop()
        except KeyboardInterrupt:
            self.shutdown()
            return

    def base_packet(self):
        packet_out = packets.Packet()
        if (not self.args.no_send_version) or (self.args.notice):
            packet_out.opcodes[packets.OpcodeExtended.id] = packets.OpcodeExtended()
        if not self.args.no_send_version:
            packet_out.opcodes[packets.OpcodeExtended.id].segments[packets.ExtendedVersion.id] = packets.ExtendedVersion()
            packet_out.opcodes[packets.OpcodeExtended.id].segments[packets.ExtendedVersion.id].text = version_string
        if self.args.notice:
            packet_out.opcodes[packets.OpcodeExtended.id].segments[packets.ExtendedNotice.id] = packets.ExtendedNotice()
            packet_out.opcodes[packets.OpcodeExtended.id].segments[packets.ExtendedNotice.id].text = self.args.notice
        if self.args.auth:
            packet_out.opcodes[packets.OpcodeHMAC.id] = packets.OpcodeHMAC()
            packet_out.opcodes[packets.OpcodeHMAC.id].key = bytearray(self.args.auth)
            packet_out.opcodes[packets.OpcodeHMAC.id].digest_index = self.args.auth_digest_index
        packet_out.padding_pattern = self.args.pattern_bytearray
        packet_out.min_length = self.args.min_packet_size
        packet_out.max_length = self.args.max_packet_size
        return packet_out

    def scheduled_cleanup(self):
        self.print_debug('Cleanup')
        for sock_class in self.sock_classes:
            self.scheduled_cleanup_sock_class(sock_class)

    def scheduled_cleanup_sock_class(self, sock_class):
        now = clock()
        for peer_tuple in sock_class.sent_messages.keys():
            for message_id_int in sock_class.sent_messages[peer_tuple].keys():
                if now > (sock_class.sent_messages[peer_tuple][message_id_int][0] + 120.0):
                    del(sock_class.sent_messages[peer_tuple][message_id_int])
                    self.print_debug('Cleanup: Removed sent_messages %s %d' % (repr(peer_tuple), message_id_int))
            if len(sock_class.sent_messages[peer_tuple]) == 0:
                del(sock_class.sent_messages[peer_tuple])
                self.print_debug('Cleanup: Removed sent_messages empty %s' % repr(peer_tuple))
        for peer_tuple in sock_class.seen_messages.keys():
            for message_id_int in sock_class.seen_messages[peer_tuple].keys():
                if now > (sock_class.seen_messages[peer_tuple][message_id_int] + 600.0):
                    del(sock_class.seen_messages[peer_tuple][message_id_int])
                    self.print_debug('Cleanup: Removed seen_messages %s %d' % (repr(peer_tuple), message_id_int))
            if len(sock_class.seen_messages[peer_tuple]) == 0:
                del(sock_class.seen_messages[peer_tuple])
                self.print_debug('Cleanup: Removed seen_messages empty %s' % repr(peer_tuple))
        for peer_tuple in sock_class.courtesy_messages.keys():
            for message_id_int in sock_class.courtesy_messages[peer_tuple].keys():
                if now > (sock_class.courtesy_messages[peer_tuple][message_id_int][0] + 120.0):
                    del(sock_class.courtesy_messages[peer_tuple][message_id_int])
                    self.print_debug('Cleanup: Removed courtesy_messages %s %d' % (repr(peer_tuple), message_id_int))
            if len(sock_class.courtesy_messages[peer_tuple]) == 0:
                del(sock_class.courtesy_messages[peer_tuple])
                self.print_debug('Cleanup: Removed courtesy_messages empty %s' % repr(peer_tuple))

    def new_socket(self, family, type, bind):
        sock = socket.socket(family, type)
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
        self.print_debug('Bound to: %s' % repr((family, type, bind)))
        return sock

    def loop(self):
        while True:
            now = clock()
            if now >= self.next_cleanup:
                self.scheduled_cleanup()
                self.next_cleanup = now + 60.0
            if not self.args.listen:
                for sock_class in self.sock_classes:
                    if sock_class.is_shutdown:
                        continue
                    if now >= sock_class.next_send:
                        if self.args.count and (sock_class.pings_transmitted >= self.args.count):
                            sock_class.is_shutdown = True
                            continue
                        if (sock_class.pings_transmitted == 0) and (self.args.preload > 1):
                            for i in xrange(self.args.preload):
                                self.send_new_ping(sock_class, sock_class.client_host[4])
                        else:
                            self.send_new_ping(sock_class, sock_class.client_host[4])
                        sock_class.next_send = now + self.args.interval

            if self.args.flood:
                next_send = now + 0.01
                for sock_class in self.sock_classes:
                    if next_send < sock_class.next_send:
                        sock_class.next_send = next_send

            next_wakeup = now + self.old_age_interval
            next_wakeup_reason = 'old age'
            for sock_class in self.sock_classes:
                if (not self.args.listen) and (sock_class.next_send < next_wakeup):
                    next_wakeup = sock_class.next_send
                    next_wakeup_reason = 'send'
            if self.args.stats:
                if now >= self.next_stats:
                    self.print_stats(short=True)
                    self.next_stats = now + self.args.stats
                if self.next_stats < next_wakeup:
                    next_wakeup = self.next_stats
                    next_wakeup_reason = 'stats'
            if self.args.deadline:
                time_deadline = self.time_start + self.args.deadline
                if now >= time_deadline:
                    self.shutdown()
                if time_deadline < next_wakeup:
                    next_wakeup = time_deadline
                    next_wakeup_reason = 'deadline'
            if self.next_cleanup < next_wakeup:
                next_wakeup = self.next_cleanup
                next_wakeup_reason = 'cleanup'

            if next_wakeup < now:
                next_wakeup = now
                next_wakeup_reason = 'time travel'
            self.print_debug('Next wakeup: %s (%s)' % ((next_wakeup - now), next_wakeup_reason))

            for sock_class in self.poller.poll(next_wakeup - now):
                try:
                    self.process_incoming_packet(sock_class)
                except Exception as e:
                    self.print_out('Exception: %s' % str(e))
                    if self.args.debug:
                        raise

                if self.args.adaptive and sock_class.rtt_ewma:
                    target = sock_class.rtt_ewma / 8.0 / 1000.0
                    sock_class.next_send = now + target
                if (
                    self.args.count and
                    (sock_class.pings_transmitted >= self.args.count) and
                    (sock_class.pings_transmitted == sock_class.pings_received)
                ):
                    sock_class.is_shutdown = True

            all_shutdown = True
            for sock_class in self.sock_classes:
                if not sock_class.is_shutdown:
                    all_shutdown = False
                    break
            if all_shutdown:
                self.shutdown()


def main():
    args = parse_args()
    t = TwoPing(args)
    return(t.run())


if __name__ == '__main__':
    sys.exit(main())
