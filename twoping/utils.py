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


def twoping_checksum(d):
    checksum = 0

    for i in xrange(len(d)):
        if i & 1:
            checksum += d[i]
        else:
            checksum += d[i] << 8

    checksum = ((checksum >> 16) + (checksum & 0xffff))
    checksum = ((checksum >> 16) + (checksum & 0xffff))
    checksum = ~checksum & 0xffff

    if checksum == 0:
        checksum = 0xffff

    return checksum


def lazy_div(n, d):
    if d == 0:
        return 0
    return n / d


def int_to_bytearray(i, minimum=1):
    out = bytearray()
    while i >= 256:
        out.insert(0, i & 0xff)
        i = i >> 8
    out.insert(0, i)
    out_len = len(out)
    if out_len < minimum:
        out = bytearray(minimum - out_len) + out
    return out


def bytearray_to_int(b):
    out = 0
    for x in b:
        out = (out << 8) + x
    return out
