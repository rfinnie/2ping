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

import gettext
import platform
import random as _pyrandom

try:
    import distro
except ImportError as e:
    distro = e


_ = gettext.translation("2ping", fallback=True).gettext
_pl = gettext.translation("2ping", fallback=True).ngettext

try:
    random = _pyrandom.SystemRandom()
    random_is_systemrandom = True
except AttributeError:
    random = _pyrandom
    random_is_systemrandom = False


def twoping_checksum(d):
    checksum = 0

    if (len(d) % 2) == 1:
        # Convert from (possible) bytearray to bytes before appending
        d = bytes(d) + b"\x00"

    for i in range(0, len(d), 2):
        checksum = checksum + (d[i] << 8) + d[i + 1]
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    checksum = ~checksum & 0xFFFF

    if checksum == 0:
        checksum = 0xFFFF

    return checksum


def lazy_div(n, d):
    if d == 0:
        return 0
    return n / d


def npack(i, minimum=1):
    out = bytearray()
    while i >= 256:
        out.insert(0, i & 0xFF)
        i = i >> 8
    out.insert(0, i)
    out_len = len(out)
    if out_len < minimum:
        out = bytearray(minimum - out_len) + out
    return bytes(out)


def nunpack(b):
    out = 0
    for x in b:
        out = (out << 8) + x
    return out


def platform_info():
    platform_name = platform.system()
    platform_machine = platform.machine()
    platform_info = "{} {}".format(platform_name, platform_machine)
    distro_name = ""
    distro_version = ""
    distro_info = ""
    if not isinstance(distro, ImportError):
        if hasattr(distro, "name"):
            distro_name = distro.name()
        if hasattr(distro, "version"):
            distro_version = distro.version()
    if distro_name:
        distro_info = distro_name
        if distro_version:
            distro_info += " " + distro_version
        return "{} ({})".format(platform_info, distro_info)
    else:
        return platform_info


def fuzz_bytearray(data, percent, start=0, end=None):
    if end is None:
        end = len(data)
    for p in range(start, end):
        xor_byte = 0
        for i in range(8):
            if random.random() < (percent / 100.0):
                xor_byte = xor_byte + (2 ** i)
        data[p] = data[p] ^ xor_byte


def fuzz_packet(packet, percent):
    packet = bytearray(packet)

    # Fuzz the entire packet
    fuzz_bytearray(packet, percent, 4)

    # Fuzz the magic number, at a lower probability
    fuzz_bytearray(packet, percent / 10.0, 0, 2)

    # Recalculate the checksum
    packet[2:4] = b"\x00\x00"
    packet[2:4] = npack(twoping_checksum(packet), 2)

    # Fuzz the recalculated checksum itself, at a lower probability
    fuzz_bytearray(packet, percent / 10.0, 2, 4)

    return bytes(packet)
