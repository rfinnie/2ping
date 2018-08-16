# 2ping - A bi-directional ping utility
# Copyright (C) 2010-2018 Ryan Finnie
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

import sys
import os
import argparse
from . import __version__
from .utils import _


def parse_args(argv=None):
    if argv is None:
        argv = sys.argv

    if argv[0].endswith('2ping6'):
        ipv6_default = True
    else:
        ipv6_default = False

    parser = argparse.ArgumentParser(
        description='2ping ({})'.format(__version__),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        prog=os.path.basename(argv[0]),
    )
    parser.add_argument(
        '--version', '-V', action='version',
        version=__version__,
        help=_('report the program version'),
    )

    # Positionals
    parser.add_argument(
        'host', type=str, default=None, nargs='*',
        help=_('host to ping'),
    )

    # ping-compatible options
    parser.add_argument(
        '--audible', '-a', dest='audible', action='store_true',
        help=_('audible ping'),
    )
    parser.add_argument(
        '--adaptive', '-A', dest='adaptive', action='store_true',
        help=_('adaptive RTT ping'),
    )
    parser.add_argument(
        '--count', '-c', dest='count', type=int,
        help=_('number of pings to send'),
    )
    parser.add_argument(
        '--flood', '-f', dest='flood', action='store_true',
        help=_('flood mode'),
    )
    parser.add_argument(
        '--interval', '-i', dest='interval', type=float, default=1.0,
        help=_('seconds between pings'), metavar='SECONDS',
    )
    parser.add_argument(
        '--interface-address', '-I', dest='interface_address', type=str, action='append',
        help=_('interface bind address'), metavar='ADDRESS',
    )
    parser.add_argument(
        '--preload', '-l', dest='preload', type=int, default=1,
        help=_('number of pings to send at start'), metavar='COUNT',
    )
    parser.add_argument(
        '--pattern', '-p', dest='pattern', type=str,
        help=_('hex pattern for padding'), metavar='HEX_BYTES',
    )
    parser.add_argument(
        '--quiet', '-q', dest='quiet', action='store_true',
        help=_('quiet mode'),
    )
    parser.add_argument(
        '--packetsize-compat', '-s', dest='packetsize_compat', type=int,
        help=_('packet size (ping compatible)'), metavar='BYTES',
    )
    parser.add_argument(
        '--verbose', '-v', dest='verbose', action='store_true',
        help=_('verbose mode'),
    )
    parser.add_argument(
        '--deadline', '-w', dest='deadline', type=float,
        help=_('maximum run time'), metavar='SECONDS',
    )

    # 2ping options
    parser.add_argument(
        '--all-interfaces', action='store_true',
        help=_('listen on all possible interface IPs'),
    )
    parser.add_argument(
        '--auth', type=str,
        help=_('HMAC authentication key'), metavar='KEY',
    )
    parser.add_argument(
        '--auth-digest', type=str, default='hmac-md5',
        choices=['hmac-md5', 'hmac-sha1', 'hmac-sha256', 'hmac-crc32', 'hmac-sha512'],
        help=_('HMAC authentication digest'), metavar='DIGEST',
    )
    parser.add_argument(
        '--debug', action='store_true',
        help=_('debug mode'),
    )
    parser.add_argument(
        '--encrypt', type=str,
        help=_('Encryption key'), metavar='KEY',
    )
    parser.add_argument(
        '--encrypt-method', type=str, default='hkdf-aes256-cbc',
        choices=['hkdf-aes256-cbc'],
        help=_('Encryption method'), metavar='METHOD',
    )
    parser.add_argument(
        '--fuzz', type=float,
        help=_('incoming fuzz percentage'), metavar='PERCENT',
    )
    parser.add_argument(
        '--inquire-wait', type=float, default=10.0,
        help=_('maximum time before loss inquiries'), metavar='SECONDS',
    )
    parser.add_argument(
        '--ipv4', '-4', action='store_true',
        help=_('force IPv4'),
    )
    parser.add_argument(
        '--ipv6', '-6', action='store_true', default=ipv6_default,
        help=_('force IPv6'),
    )
    parser.add_argument(
        '--listen', action='store_true',
        help=_('listen mode'),
    )
    parser.add_argument(
        '--max-packet-size', type=int, default=512,
        help=_('maximum packet size'), metavar='BYTES',
    )
    parser.add_argument(
        '--min-packet-size', type=int, default=128,
        help=_('minimum packet size'), metavar='BYTES',
    )
    parser.add_argument(
        '--nagios', type=str,
        help=_('nagios-compatible output'), metavar='WRTA,WLOSS%,CRTA,CLOSS%',
    )
    parser.add_argument(
        '--no-3way', action='store_true',
        help=_('do not send 3-way pings'),
    )
    parser.add_argument(
        '--no-match-packet-size', action='store_true',
        help=_('do not match packet size of peer'),
    )
    parser.add_argument(
        '--no-send-version', action='store_true',
        help=_('do not send program version to peers'),
    )
    parser.add_argument(
        '--notice', type=str,
        help=_('arbitrary notice text'), metavar='TEXT',
    )
    parser.add_argument(
        '--packet-loss', type=str,
        help=_('percentage simulated packet loss'), metavar='OUT:IN',
    )
    parser.add_argument(
        '--port', type=str, default='15998',
        help=_('port to connect / bind to'),
    )
    parser.add_argument(
        '--send-monotonic-clock', action='store_true',
        help=_('send monotonic clock to peers'),
    )
    parser.add_argument(
        '--send-random', type=int,
        help=_('send random data to peers'), metavar='BYTES',
    )
    parser.add_argument(
        '--send-time', action='store_true',
        help=_('send wall clock time to peers'),
    )
    parser.add_argument(
        '--stats', type=float,
        help=_('print recurring statistics'), metavar='SECONDS',
    )
    parser.add_argument(
        '--srv', action='store_true',
        help=_('lookup SRV records in client mode'),
    )
    parser.add_argument(
        '--srv-service', type=str, default='2ping',
        help=_('service name for SRV lookups'),
    )

    # ping-compatible ignored options
    for opt in 'b|B|d|L|n|R|r|U'.split('|'):
        parser.add_argument(
            '-{}'.format(opt), action='store_true',
            dest='ignored_{}'.format(opt),
            help=argparse.SUPPRESS,
        )
    for opt in 'F|Q|S|t|T|M|W'.split('|'):
        parser.add_argument(
            '-{}'.format(opt), type=str, default=None,
            dest='ignored_{}'.format(opt),
            help=argparse.SUPPRESS,
        )

    args = parser.parse_args(args=argv[1:])

    if (not args.listen) and (not args.host):
        parser.print_help()
        parser.exit()
    if args.nagios:
        args.quiet = True
        if (not args.count) and (not args.deadline):
            args.count = 5
        nagios_opts = args.nagios.split(',')
        if len(nagios_opts) != 4:
            parser.error(_('Invalid limits'))
        (
            args.nagios_warn_rta,
            args.nagios_warn_loss,
            args.nagios_crit_rta,
            args.nagios_crit_loss,
        ) = nagios_opts
        if args.nagios_warn_loss[-1:] != '%':
            parser.error(_('Invalid limits'))
        if args.nagios_crit_loss[-1:] != '%':
            parser.error(_('Invalid limits'))
        try:
            args.nagios_warn_loss = float(args.nagios_warn_loss[:-1])
            args.nagios_crit_loss = float(args.nagios_crit_loss[:-1])
            args.nagios_warn_rta = float(args.nagios_warn_rta)
            args.nagios_crit_rta = float(args.nagios_crit_rta)
        except ValueError as e:
            parser.error(e.message)
    if args.packetsize_compat:
        args.min_packet_size = args.packetsize_compat + 8
    if args.max_packet_size < args.min_packet_size:
        parser.error(_('Maximum packet size must be at least minimum packet size'))
    if args.max_packet_size < 64:
        parser.error(_('Maximum packet size must be at least 64'))
    args.packet_loss_in = 0
    args.packet_loss_out = 0
    if args.packet_loss:
        if ':' in args.packet_loss:
            (v_out, v_in) = args.packet_loss.split(':', 1)
            try:
                args.packet_loss_out = float(v_out)
                args.packet_loss_in = float(v_in)
            except ValueError as e:
                parser.error(e.message)
        else:
            try:
                args.packet_loss_in = args.packet_loss_out = float(args.packet_loss)
            except ValueError as e:
                parser.error(_('Packet loss: {error}').format(error=e.message))
    if args.pattern:
        if len(args.pattern) & 1:
            parser.error(_('Pattern must be full bytes'))
        if len(args.pattern) > 32:
            parser.error(_('Pattern must be 16 bytes or less'))
        args.pattern_bytes = b''
        for i in range(int(len(args.pattern) / 2)):
            a = args.pattern[(i*2):(i*2+2)]
            try:
                b = int(a, 16)
            except ValueError as e:
                parser.error(_('Pattern: {error}').format(error=e.message))
            args.pattern_bytes += bytes([b])
    else:
        args.pattern_bytes = b'\x00'

    hmac_id_map = {
        'hmac-md5': 1,
        'hmac-sha1': 2,
        'hmac-sha256': 3,
        'hmac-crc32': 4,
        'hmac-sha512': 5,
    }
    args.auth_digest_index = hmac_id_map[args.auth_digest]

    if args.encrypt:
        try:
            from Crypto.Cipher import AES
        except ImportError:
            parser.error(_('Python crypto module required for encryption'))

    encrypt_id_map = {
        'hkdf-aes256-cbc': 1,
    }
    args.encrypt_method_index = encrypt_id_map[args.encrypt_method]

    if args.debug:
        args.verbose = True

    return args
