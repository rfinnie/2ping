# 2ping - A bi-directional ping utility
# Copyright (C) 2010-2021 Ryan Finnie
# SPDX-License-Identifier: MPL-2.0

import argparse
import os
import socket
import sys
import types

from . import __version__, packets
from .utils import _, AES


def _type_nagios(string):
    (warn_rta, warn_loss, crit_rta, crit_loss) = string.split(",", 3)
    if (warn_loss[-1:] != "%") or (crit_loss[-1:] != "%"):
        raise argparse.ArgumentTypeError(_("Invalid limits"))
    return types.SimpleNamespace(
        warn_rta=float(warn_rta),
        warn_loss=float(warn_loss[:-1]),
        crit_rta=float(crit_rta),
        crit_loss=float(crit_loss[:-1]),
    )


def _type_packet_loss(string):
    if ":" in string:
        (v_out, v_in) = string.split(":", 1)
    else:
        v_out = v_in = string
    return types.SimpleNamespace(out_pct=float(v_out), in_pct=float(v_in))


def parse_args(argv=None):
    if argv is None:
        argv = sys.argv

    if argv[0].endswith("2ping6"):
        ipv6_default = True
    else:
        ipv6_default = False

    parser = argparse.ArgumentParser(
        description="2ping ({})".format(__version__),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        prog=os.path.basename(argv[0]),
    )
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=__version__,
        help=_("report the program version"),
    )

    # Positionals
    parser.add_argument(
        "host", type=str, default=None, nargs="*", help=_("host to ping")
    )

    # ping-compatible options
    ping_group = parser.add_argument_group(title=_("ping-compatible options"))

    ping_group.add_argument(
        "--audible", "-a", dest="audible", action="store_true", help=_("audible ping")
    )
    ping_group.add_argument(
        "--adaptive",
        "-A",
        dest="adaptive",
        action="store_true",
        help=_("adaptive RTT ping"),
    )
    ping_group.add_argument(
        "--count", "-c", dest="count", type=int, help=_("number of pings to send")
    )
    ping_group.add_argument(
        "--flood", "-f", dest="flood", action="store_true", help=_("flood mode")
    )
    ping_group.add_argument(
        "--interval",
        "-i",
        dest="interval",
        type=float,
        default=1.0,
        help=_("seconds between pings"),
        metavar="SECONDS",
    )
    ping_group.add_argument(
        "--interface-address",
        "-I",
        dest="interface_address",
        type=str,
        action="append",
        default=[],
        help=_("interface bind address"),
        metavar="ADDRESS",
    )
    ping_group.add_argument(
        "--preload",
        "-l",
        dest="preload",
        type=int,
        default=1,
        help=_("number of pings to send at start"),
        metavar="COUNT",
    )
    ping_group.add_argument(
        "--pattern",
        "-p",
        dest="pattern",
        type=lambda string: bytes.fromhex(string),
        default="00",
        help=_("hex pattern for padding"),
        metavar="HEX_BYTES",
    )
    ping_group.add_argument(
        "--quiet", "-q", dest="quiet", action="store_true", help=_("quiet mode")
    )
    ping_group.add_argument(
        "--packetsize-compat",
        "-s",
        dest="packetsize_compat",
        type=int,
        help=_("packet size (ping compatible)"),
        metavar="BYTES",
    )
    ping_group.add_argument(
        "--verbose", "-v", dest="verbose", action="store_true", help=_("verbose mode")
    )
    ping_group.add_argument(
        "--deadline",
        "-w",
        dest="deadline",
        type=float,
        help=_("maximum run time"),
        metavar="SECONDS",
    )

    # 2ping options
    twoping_group = parser.add_argument_group(title=_("2ping-specific options"))

    twoping_group.add_argument(
        "--auth", type=str, help=_("HMAC authentication key"), metavar="KEY"
    )
    twoping_group.add_argument(
        "--auth-digest",
        type=str,
        default="hmac-md5",
        choices=[x[2].lower() for x in packets.OpcodeHMAC().digest_map.values()],
        help=_("HMAC authentication digest"),
        metavar="DIGEST",
    )
    twoping_group.add_argument("--debug", action="store_true", help=_("debug mode"))
    twoping_group.add_argument(
        "--encrypt", type=str, help=_("Encryption key"), metavar="KEY"
    )
    twoping_group.add_argument(
        "--encrypt-method",
        type=str,
        default="hkdf-aes256-cbc",
        choices=[x[0].lower() for x in packets.OpcodeEncrypted().method_map.values()],
        help=_("Encryption method"),
        metavar="METHOD",
    )
    twoping_group.add_argument(
        "--fuzz", type=float, help=_("incoming fuzz percentage"), metavar="PERCENT"
    )
    twoping_group.add_argument(
        "--inquire-wait",
        type=float,
        default=10.0,
        help=_("maximum time before loss inquiries"),
        metavar="SECONDS",
    )
    twoping_group.add_argument(
        "--ipv4", "-4", action="store_true", help=_("force IPv4")
    )
    twoping_group.add_argument(
        "--ipv6", "-6", action="store_true", default=ipv6_default, help=_("force IPv6")
    )
    twoping_group.add_argument("--listen", action="store_true", help=_("listen mode"))
    twoping_group.add_argument(
        "--loopback", action="store_true", help=_("UNIX loopback test mode")
    )
    twoping_group.add_argument(
        "--loopback-pairs",
        type=int,
        default=1,
        help=_("number of loopback pairs to create"),
        metavar="PAIRS",
    )
    twoping_group.add_argument(
        "--max-packet-size",
        type=int,
        default=512,
        help=_("maximum packet size"),
        metavar="BYTES",
    )
    twoping_group.add_argument(
        "--min-packet-size",
        type=int,
        default=128,
        help=_("minimum packet size"),
        metavar="BYTES",
    )
    twoping_group.add_argument(
        "--nagios",
        type=_type_nagios,
        help=_("nagios-compatible output"),
        metavar="WRTA,WLOSS%,CRTA,CLOSS%",
    )
    twoping_group.add_argument(
        "--no-3way", action="store_true", help=_("do not send 3-way pings")
    )
    twoping_group.add_argument(
        "--no-match-packet-size",
        action="store_true",
        help=_("do not match packet size of peer"),
    )
    twoping_group.add_argument(
        "--no-send-version",
        action="store_true",
        help=_("do not send program version to peers"),
    )
    twoping_group.add_argument(
        "--notice", type=str, help=_("arbitrary notice text"), metavar="TEXT"
    )
    twoping_group.add_argument(
        "--packet-loss",
        type=_type_packet_loss,
        help=_("percentage simulated packet loss"),
        metavar="OUT:IN",
    )
    twoping_group.add_argument(
        "--port", type=str, default="15998", help=_("port to connect / bind to")
    )
    twoping_group.add_argument(
        "--send-monotonic-clock",
        action="store_true",
        help=_("send monotonic clock to peers"),
    )
    twoping_group.add_argument(
        "--send-random", type=int, help=_("send random data to peers"), metavar="BYTES"
    )
    twoping_group.add_argument(
        "--send-time", action="store_true", help=_("send wall clock time to peers")
    )
    twoping_group.add_argument(
        "--stats", type=float, help=_("print recurring statistics"), metavar="SECONDS"
    )
    twoping_group.add_argument(
        "--srv", action="store_true", help=_("lookup SRV records in client mode")
    )
    twoping_group.add_argument(
        "--srv-service",
        type=str,
        default="2ping",
        help=_("service name for SRV lookups"),
    )
    twoping_group.add_argument(
        "--subtract-peer-host-latency",
        action="store_true",
        help=_("subtract peer host latency from RTT calculations, if sent"),
    )

    # ping-compatible ignored options
    for opt in "b|B|d|L|n|R|r|U".split("|"):
        parser.add_argument(
            "-{}".format(opt),
            action="store_true",
            dest="ignored_{}".format(opt),
            help=argparse.SUPPRESS,
        )
    for opt in "F|Q|S|t|T|M|W".split("|"):
        parser.add_argument(
            "-{}".format(opt),
            type=str,
            default=None,
            dest="ignored_{}".format(opt),
            help=argparse.SUPPRESS,
        )

    # Deprecated ignored options
    parser.add_argument("--all-interfaces", action="store_true", help=argparse.SUPPRESS)

    args = parser.parse_args(args=argv[1:])

    if (not args.listen) and (not args.host) and (not args.loopback):
        parser.print_help()
        parser.exit()
    if args.loopback and not hasattr(socket, "AF_UNIX"):
        parser.error("--loopback not supported on non-UNIX platforms")
    if args.nagios:
        args.quiet = True
        if (not args.count) and (not args.deadline):
            args.count = 5
    if args.packetsize_compat:
        args.min_packet_size = args.packetsize_compat + 8
    if args.max_packet_size < args.min_packet_size:
        parser.error(_("Maximum packet size must be at least minimum packet size"))
    if args.max_packet_size < 64:
        parser.error(_("Maximum packet size must be at least 64"))

    if args.encrypt and isinstance(AES, ImportError):
        parser.error(_("Crypto module required for encryption"))

    if args.debug:
        args.verbose = True

    return args
