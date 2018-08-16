#!/usr/bin/env python3

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

import binascii
import copy

digest_size = 4


class CRC32():
    digest_size = 4
    block_size = 64
    _crc = 0

    def __init__(self, buf=None):
        if buf is not None:
            self.update(buf)

    def copy(self):
        return copy.copy(self)

    def update(self, buf):
        self._crc = binascii.crc32(buf, self._crc)

    def clear(self):
        self._crc = 0

    def digest(self):
        i = self._crc & 0xffffffff
        out = bytearray()
        while i >= 256:
            out.insert(0, i & 0xff)
            i = i >> 8
        out.insert(0, i)
        out_len = len(out)
        if out_len < 4:
            out = bytearray(4 - out_len) + out
        return out

    def hexdigest(self):
        return ''.join('{hex:02x}'.format(hex=x) for x in self.digest())


def new(buf=None):
    return CRC32(buf)


if __name__ == '__main__':
    import sys
    files = sys.argv[1:]
    if len(files) == 0:
        if hasattr(sys.stdin, 'buffer'):
            stdin = sys.stdin.buffer
        else:
            stdin = sys.stdin
        c = new()
        for buf in stdin.readlines():
            c.update(buf)
        print(c.hexdigest())
    else:
        for file in files:
            with open(file, 'rb') as f:
                c = new()
                for buf in f.readlines():
                    c.update(buf)
                if len(files) > 1:
                    print('{}\t{}'.format(c.hexdigest(), file))
                else:
                    print(c.hexdigest())
