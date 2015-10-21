#!/usr/bin/env python

from __future__ import print_function, division
import random
import socket
import select
import math
import signal
import sys
import errno
from . import __version__
from . import packets
from .monotonic_clock import MonotonicClock
from .args import parse_args
from .utils import lazy_div, bytearray_to_int


mc_instance = MonotonicClock()
clock = mc_instance.clock


class TwoPing():
    def __init__(self, args):
        now = clock()
        self.args = args
        self.time_start = now

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
        # Current position of a 5-tuple's incrementing ping integer.
        self.ping_positions = {}
        # List of socket objects.
        self.sockets = []
        # Used during client mode for the host tuple to send UDP packets to.
        self.host_info = None

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

        # Scheduled events
        self.next_cleanup = now + 60.0
        self.next_send = 0
        self.next_stats = 0
        if self.args.stats:
            self.next_stats = now + self.args.stats

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

    def process_incoming_packet(self, sock):
        try:
            (data, peer_address) = sock.recvfrom(16384)
        except socket.error as e:
            # Errors from the last send() can be trapped via IP_RECVERR (Linux only).
            self.errors_received += 1
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
            except:
                if self.args.quiet:
                    pass
                elif self.args.flood:
                    self.print_out('\x08E', end='', flush=True)
                else:
                    self.print_out(error_string)
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
        calculated_rtt = None

        time_begin = clock()
        peer_tuple = (socket_address, peer_address, sock.type)

        # Preload state tables if the client has not been seen (or has been cleaned).
        if peer_tuple not in self.seen_messages:
            self.seen_messages[peer_tuple] = {}
        if peer_tuple not in self.sent_messages:
            self.sent_messages[peer_tuple] = {}
        if peer_tuple not in self.courtesy_messages:
            self.courtesy_messages[peer_tuple] = {}
        if peer_tuple not in self.ping_positions:
            self.ping_positions[peer_tuple] = 0

        # Load/parse the packet.
        packet_in = packets.Packet()
        packet_in.load(data)
        if self.args.verbose:
            self.print_out('RECV: %s' % repr(packet_in))

        # Verify HMAC if required.
        if self.args.auth:
            if packets.OpcodeHMAC.id not in packet_in.opcodes:
                self.errors_received += 1
                self.print_out('Auth required but not provided by %s' % peer_address[0])
                return
            if packet_in.opcodes[packets.OpcodeHMAC.id].digest_index != self.args.auth_digest_index:
                self.errors_received += 1
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
                self.print_out(
                    'Auth hash failed from %s (expected %s, got %s)' % (
                        peer_address[0],
                        ''.join('{:02x}'.format(x) for x in test_hash_calculated),
                        ''.join('{:02x}'.format(x) for x in test_hash)
                    )
                )
                return

        # Check if any invesitgations results have come back.
        self.check_investigations(peer_tuple, packet_in)
        if packets.OpcodeCourtesyExpiration.id in packet_in.opcodes:
            for message_id in packet_in.opcodes[packets.OpcodeCourtesyExpiration.id].message_ids:
                message_id_int = bytearray_to_int(message_id)
                if message_id_int in self.seen_messages[peer_tuple]:
                    del(self.seen_messages[peer_tuple][message_id_int])

        # If this is in reply to one of our sent packets, it's a ping reply, so handle it specially.
        if packets.OpcodeInReplyTo.id in packet_in.opcodes:
            replied_message_id = packet_in.opcodes[packets.OpcodeInReplyTo.id].message_id
            replied_message_id_int = bytearray_to_int(replied_message_id)
            if replied_message_id_int in self.sent_messages[peer_tuple]:
                (sent_time, _, ping_position) = self.sent_messages[peer_tuple][replied_message_id_int]
                del(self.sent_messages[peer_tuple][replied_message_id_int])
                calculated_rtt = (time_begin - sent_time) * 1000
                self.pings_received += 1
                self.update_rtts(calculated_rtt)
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
                        (packets.OpcodeExtended.id in packet_in.opcodes)
                        and (packets.ExtendedNotice.id in packet_in.opcodes[packets.OpcodeExtended.id].segments)
                    ):
                        notice = str(packet_in.opcodes[packets.OpcodeExtended.id].segments[packets.ExtendedNotice.id].text)
                        self.print_out('  Peer notice: %s' % notice)
            self.courtesy_messages[peer_tuple][replied_message_id_int] = (time_begin, replied_message_id)

        # If the peer requested a reply, prepare one.
        if packets.OpcodeReplyRequested.id in packet_in.opcodes:
            # Populate seen_messages.
            self.seen_messages[peer_tuple][bytearray_to_int(packet_in.message_id)] = time_begin

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
                    if bytearray_to_int(message_id) in self.seen_messages[peer_tuple]:
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
            self.start_investigations(peer_tuple, packet_out)

            # Any courtesy expirations we have waiting should be sent.
            if len(self.courtesy_messages[peer_tuple]) > 0:
                packet_out.opcodes[packets.OpcodeCourtesyExpiration.id] = packets.OpcodeCourtesyExpiration()
                for (courtesy_time, courtesy_message_id) in self.courtesy_messages[peer_tuple].values():
                    packet_out.opcodes[packets.OpcodeCourtesyExpiration.id].message_ids.append(courtesy_message_id)

            # Calculate the host latency as late as possible.
            packet_out.opcodes[packets.OpcodeHostLatency.id] = packets.OpcodeHostLatency()
            time_send = clock()
            packet_out.opcodes[packets.OpcodeHostLatency.id].delay_us = int((time_send - time_begin) * 1000000)

            # Dump the packet.
            dump_out = packet_out.dump()

            # Send the packet.
            self.sock_sendto(sock, dump_out, peer_address)
            self.packets_transmitted += 1

            # If ReplyRequested is set, we care about its arrival.
            if packets.OpcodeReplyRequested.id in packet_out.opcodes:
                self.pings_transmitted += 1
                self.ping_positions[peer_tuple] += 1
                self.sent_messages[peer_tuple][bytearray_to_int(packet_out.message_id)] = (
                    time_send,
                    packet_out.message_id,
                    self.ping_positions[peer_tuple]
                )

            # Examine the sent packet.
            packet_out_examine = packets.Packet()
            packet_out_examine.load(dump_out)

            # Any courtesy expirations which had room in the sent packet should be forgotten.
            if packets.OpcodeCourtesyExpiration.id in packet_out_examine.opcodes:
                for courtesy_message_id in packet_out_examine.opcodes[packets.OpcodeCourtesyExpiration.id].message_ids:
                    courtesy_message_id_int = bytearray_to_int(courtesy_message_id)
                    if courtesy_message_id_int in self.courtesy_messages[peer_tuple]:
                        del(self.courtesy_messages[peer_tuple][courtesy_message_id_int])

            if self.args.verbose:
                self.print_out('SEND: %s' % repr(packet_out_examine))

        # If we're in flood mode and this is a ping reply, send a new ping ASAP.
        if self.args.flood and (not self.args.listen) and (packets.OpcodeInReplyTo.id in packet_in.opcodes):
            self.next_send = time_begin

    def sock_sendto(self, sock, data, address):
        # Simulate random packet loss.
        if self.args.packet_loss_out and (random.random() < (self.args.packet_loss_out / 100.0)):
            return
        # Send the packet.
        sock.sendto(data, address)

    def start_investigations(self, peer_tuple, packet_check):
        if len(self.sent_messages[peer_tuple]) == 0:
            return
        if packets.OpcodeInvestigate.id in packet_check.opcodes:
            iobj = packet_check.opcodes[packets.OpcodeInvestigate.id]
        else:
            iobj = None
        now = clock()
        for message_id_str in self.sent_messages[peer_tuple]:
            (sent_time, message_id, _) = self.sent_messages[peer_tuple][message_id_str]
            if now >= (sent_time + self.args.inquire_wait):
                if iobj is None:
                    iobj = packets.OpcodeInvestigate()
                if message_id not in iobj.message_ids:
                    iobj.message_ids.append(message_id)
        if iobj is not None:
            packet_check.opcodes[packets.OpcodeInvestigate.id] = iobj

    def check_investigations(self, peer_tuple, packet_check):
        # Inbound
        if packets.OpcodeInvestigationSeen.id in packet_check.opcodes:
            for message_id in packet_check.opcodes[packets.OpcodeInvestigationSeen.id].message_ids:
                message_id_int = bytearray_to_int(message_id)
                if message_id_int not in self.sent_messages[peer_tuple]:
                    continue
                if self.args.quiet:
                    pass
                elif self.args.flood:
                    self.print_out('\x08<', end='', flush=True)
                else:
                    (_, _, ping_seq) = self.sent_messages[peer_tuple][message_id_int]
                    self.print_out('Lost inbound packet from %s: ping_seq=%d' % (peer_tuple[1][0], ping_seq))
                del(self.sent_messages[peer_tuple][message_id_int])
                self.lost_inbound += 1
        # Outbound
        if packets.OpcodeInvestigationUnseen.id in packet_check.opcodes:
            for message_id in packet_check.opcodes[packets.OpcodeInvestigationUnseen.id].message_ids:
                message_id_int = bytearray_to_int(message_id)
                if message_id_int not in self.sent_messages[peer_tuple]:
                    continue
                if self.args.quiet:
                    pass
                elif self.args.flood:
                    self.print_out('\x08>', end='', flush=True)
                else:
                    (_, _, ping_seq) = self.sent_messages[peer_tuple][message_id_int]
                    self.print_out('Lost outbound packet to %s: ping_seq=%d' % (peer_tuple[1][0], ping_seq))
                del(self.sent_messages[peer_tuple][message_id_int])
                self.lost_outbound += 1

    def setup_listener(self):
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
                if (l[0] == socket.AF_INET6) and (not self.args.ipv4):
                    pass
                elif (l[0] == socket.AF_INET) and (not self.args.ipv6):
                    pass
                else:
                    continue
                sock = self.new_socket(l[0], l[1], l[4])
                self.sockets.append(sock)
        self.print_out('2PING listener: %d to %d bytes of data.' % (self.args.min_packet_size, self.args.max_packet_size))

    def setup_client(self):
        for l in socket.getaddrinfo(self.args.host, self.args.port, socket.AF_UNSPEC, socket.SOCK_DGRAM, socket.IPPROTO_UDP):
            if (l[0] == socket.AF_INET6) and (not self.args.ipv4) and self.has_ipv6:
                self.host_info = l
                break
            elif (l[0] == socket.AF_INET) and (not self.args.ipv6):
                self.host_info = l
                break
            else:
                continue
        if self.host_info is None:
            raise socket.error('Name or service not known')

        bind_info = None
        if self.args.interface_address:
            h = self.args.interface_address[-1]
        else:
            if self.host_info[0] == socket.AF_INET6:
                h = '::'
            else:
                h = '0.0.0.0'
        for l in socket.getaddrinfo(h, 0, self.host_info[0], socket.SOCK_DGRAM, socket.IPPROTO_UDP):
            bind_info = l
            break
        if bind_info is None:
            raise Exception('Cannot find suitable bind for %s' % self.host_info[4])
        sock = self.new_socket(bind_info[0], bind_info[1], bind_info[4])
        self.sockets.append(sock)
        self.print_out(
            '2PING %s (%s): %d to %d bytes of data.' % (
                self.args.host, self.host_info[4][0], self.args.min_packet_size, self.args.max_packet_size
            )
        )

    def send_new_ping(self, sock, peer_address):
        socket_address = sock.getsockname()
        peer_tuple = (socket_address, peer_address, sock.type)
        if peer_tuple not in self.sent_messages:
            self.sent_messages[peer_tuple] = {}
        if peer_tuple not in self.ping_positions:
            self.ping_positions[peer_tuple] = 0

        packet_out = self.base_packet()
        packet_out.opcodes[packets.OpcodeReplyRequested.id] = packets.OpcodeReplyRequested()
        self.start_investigations(peer_tuple, packet_out)
        dump_out = packet_out.dump()
        now = clock()
        self.sock_sendto(sock, dump_out, peer_address)
        self.packets_transmitted += 1
        self.pings_transmitted += 1
        self.ping_positions[peer_tuple] += 1
        self.sent_messages[peer_tuple][bytearray_to_int(packet_out.message_id)] = (
            now,
            packet_out.message_id,
            self.ping_positions[peer_tuple]
        )
        packet_out_examine = packets.Packet()
        packet_out_examine.load(dump_out)
        if self.args.quiet:
            pass
        elif self.args.flood:
            self.print_out('.', end='', flush=True)
        if self.args.verbose:
            self.print_out('SEND: %s' % repr(packet_out_examine))

    def update_rtts(self, rtt):
        self.rtt_total += rtt
        self.rtt_total_sq += (rtt ** 2)
        self.rtt_count += 1
        if (rtt < self.rtt_min) or (self.rtt_min == 0):
            self.rtt_min = rtt
        if rtt > self.rtt_max:
            self.rtt_max = rtt
        if self.rtt_ewma == 0:
            self.rtt_ewma = rtt * 8.0
        else:
            self.rtt_ewma += (rtt - (self.rtt_ewma / 8.0))

    def sigquit_handler(self, signum, frame):
        self.print_stats(short=True)

    def print_stats(self, short=False):
        time_start = self.time_start
        time_end = clock()
        pings_lost = self.pings_transmitted - self.pings_received
        lost_pct = lazy_div(pings_lost, self.pings_transmitted) * 100
        lost_undetermined = pings_lost - (self.lost_outbound + self.lost_inbound)
        outbound_pct = lazy_div(self.lost_outbound, self.pings_transmitted) * 100
        inbound_pct = lazy_div(self.lost_inbound, self.pings_transmitted) * 100
        undetermined_pct = lazy_div(lost_undetermined, self.pings_transmitted) * 100
        rtt_avg = lazy_div(float(self.rtt_total), self.rtt_count)
        rtt_ewma = self.rtt_ewma / 8.0
        rtt_mdev = math.sqrt(lazy_div(self.rtt_total_sq, self.rtt_count) - (lazy_div(self.rtt_total, self.rtt_count) ** 2))
        if short:
            self.print_out(
                '\x0d%d/%d pings, %d%% loss' % (
                    self.pings_transmitted, self.pings_received, lost_pct,
                ) +
                ' (%d/%d/%d out/in/undet),' % (
                    self.lost_outbound, self.lost_inbound, lost_undetermined,
                ) +
                ' min/avg/max/ewma/mdev = %0.03f/%0.03f/%0.03f/%0.03f/%0.03f ms' % (
                    self.rtt_min, rtt_avg, rtt_ewma, self.rtt_max, rtt_mdev,
                ),
                file=sys.stderr,
            )
        else:
            self.print_out('')
            if self.args.listen:
                self.print_out('--- Listener 2ping statistics ---')
            else:
                self.print_out('--- %s 2ping statistics ---' % self.host_info[4][0])
            self.print_out('%d pings transmitted, %d received, %d%% ping loss, time %dms' % (
                self.pings_transmitted, self.pings_received, lost_pct, (time_end - time_start) * 1000)
            )
            self.print_out('%d outbound ping losses (%d%%), %d inbound (%d%%), %d undetermined (%d%%)' % (
                self.lost_outbound, outbound_pct, self.lost_inbound, inbound_pct, lost_undetermined, undetermined_pct)
            )
            self.print_out('rtt min/avg/ewma/max/mdev = %0.03f/%0.03f/%0.03f/%0.03f/%0.03f ms' % (
                self.rtt_min, rtt_avg, rtt_ewma, self.rtt_max, rtt_mdev)
            )
            self.print_out('%d raw packets transmitted, %d received' % (
                self.packets_transmitted, self.packets_received)
            )

    def run(self):
        self.print_debug('Monotonic clock: %s, clock value: %f' % (mc_instance.is_monotonic, clock()))
        if hasattr(signal, 'SIGQUIT'):
            signal.signal(signal.SIGQUIT, self.sigquit_handler)

        if self.args.listen:
            self.setup_listener()
        else:
            try:
                self.setup_client()
            except (socket.error, Exception) as e:
                self.print_out('%s: %s' % (self.args.host, str(e)))
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
            packet_out.opcodes[packets.OpcodeExtended.id].segments[packets.ExtendedVersion.id].text = '2ping %s' % __version__
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
        now = clock()
        for peer_tuple in self.sent_messages.keys():
            for message_id_int in self.sent_messages[peer_tuple].keys():
                if now > (self.sent_messages[peer_tuple][message_id_int][0] + 120.0):
                    del(self.sent_messages[peer_tuple][message_id_int])
                    self.print_debug('Cleanup: Removed sent_messages %s %d' % (repr(peer_tuple), message_id_int))
            if len(self.sent_messages[peer_tuple]) == 0:
                del(self.sent_messages[peer_tuple])
                self.print_debug('Cleanup: Removed sent_messages empty %s' % repr(peer_tuple))
        for peer_tuple in self.seen_messages.keys():
            for message_id_int in self.seen_messages[peer_tuple].keys():
                if now > (self.seen_messages[peer_tuple][message_id_int] + 600.0):
                    del(self.seen_messages[peer_tuple][message_id_int])
                    self.print_debug('Cleanup: Removed seen_messages %s %d' % (repr(peer_tuple), message_id_int))
            if len(self.seen_messages[peer_tuple]) == 0:
                del(self.seen_messages[peer_tuple])
                self.print_debug('Cleanup: Removed seen_messages empty %s' % repr(peer_tuple))
        for peer_tuple in self.courtesy_messages.keys():
            for message_id_int in self.courtesy_messages[peer_tuple].keys():
                if now > (self.courtesy_messages[peer_tuple][message_id_int][0] + 120.0):
                    del(self.courtesy_messages[peer_tuple][message_id_int])
                    self.print_debug('Cleanup: Removed courtesy_messages %s %d' % (repr(peer_tuple), message_id_int))
            if len(self.courtesy_messages[peer_tuple]) == 0:
                del(self.courtesy_messages[peer_tuple])
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
                if now >= self.next_send:
                    if self.args.count and (self.pings_transmitted >= self.args.count):
                        self.shutdown()
                    if (self.pings_transmitted == 0) and (self.args.preload > 1):
                        for i in xrange(self.args.preload):
                            self.send_new_ping(self.sockets[0], self.host_info[4])
                    else:
                        self.send_new_ping(self.sockets[0], self.host_info[4])
                    if self.args.adaptive and self.rtt_ewma:
                        target = self.rtt_ewma / 8.0 / 1000.0
                        self.next_send = now + target
                    else:
                        self.next_send = now + self.args.interval

            if self.args.flood:
                next_send = now + 0.01
                if next_send < self.next_send:
                    self.next_send = next_send

            next_wakeup = now + 60.0
            next_wakeup_reason = 'old age'
            if (not self.args.listen) and (self.next_send < next_wakeup):
                next_wakeup = self.next_send
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
            try:
                select_res = select.select(self.sockets, [], [], (next_wakeup - now))
            except select.error as e:
                # EINTR: Interrupted system call (from signals)
                if e.args[0] not in (errno.EINTR,):
                    raise
                select_res = ([], [], [])
            for sock in select_res[0]:
                try:
                    self.process_incoming_packet(sock)
                except Exception as e:
                    self.print_out('Exception: %s' % str(e))
                    if self.args.debug:
                        raise


def main():
    args = parse_args()
    t = TwoPing(args)
    return(t.run())


if __name__ == '__main__':
    sys.exit(main())
