# SPDX-PackageSummary: 2ping - A bi-directional ping utility
# SPDX-FileCopyrightText: Copyright (C) 2010-2025 Ryan Finnie
# SPDX-License-Identifier: MPL-2.0

import binascii
import copy
import sys

digest_size = 4


class CRC32:
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
        i = self._crc & 0xFFFFFFFF
        out = bytearray()
        while i >= 256:
            out.insert(0, i & 0xFF)
            i = i >> 8
        out.insert(0, i)
        out_len = len(out)
        if out_len < 4:
            out = bytearray(4 - out_len) + out
        return out

    def hexdigest(self):
        return self.digest().hex()


def new(buf=None):
    return CRC32(buf)


def main(argv):
    if argv is None:
        argv = sys.argv

    files = argv[1:]
    if len(files) == 0:
        files = ["-"]

    for file in files:
        c = new()
        if file == "-":
            for buf in sys.stdin.buffer.readlines():
                c.update(buf)
        else:
            with open(file, "rb") as f:
                for buf in f.readlines():
                    c.update(buf)
        print("{}\t{}".format(c.hexdigest(), file))


def module_init():
    if __name__ == "__main__":
        sys.exit(main(sys.argv))


module_init()
