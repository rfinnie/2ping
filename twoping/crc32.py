#!/usr/bin/env python

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
        return ''.join('{:02x}'.format(x) for x in self.digest())


def new(buf=None):
    return CRC32(buf)


if __name__ == '__main__':
    import sys
    files = sys.argv[1:]
    if len(files) == 0:
        c = new()
        for line in sys.stdin.readlines():
            c.update(line)
        print c.hexdigest()
    else:
        for file in files:
            with open(file) as f:
                c = new()
                for line in f.readlines():
                    c.update(line)
                if len(files) > 1:
                    print '%s\t%s' % (c.hexdigest(), file)
                else:
                    print c.hexdigest()
