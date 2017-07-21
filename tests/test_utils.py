#!/usr/bin/env python3

import unittest
from twoping import utils


class TestUtils(unittest.TestCase):
    def test_twoping_checksum_hello(self):
        data = b'Hello World'
        self.assertEqual(utils.twoping_checksum(data), 0xae31)

    def test_twoping_checksum_junk(self):
        data = b'E\xc6\xca\x92\x10\x0e\xb1\xcf\x98\x88\x0bB\xc0\xf8X\xac\xd9\x81v\xc0E\x8co\x04\x9c\x0e\x93\xb3' + \
            b'I=8m\xb7\xd5\x86\xa7f,2\x15\xd9\x7f\xad>\x1a\xe09\x89J\xdd\x0b(\xa0\x07aGT\xc6P\x04-(NH<@\xc7\xdb' + \
            b'\x82\xfa\x0b\xab7n#^\x80\xab\xb9\xe5\x05\x14\xb1\xfcrT7\x8af\xf2Q\xa1w\xda\xd5\x88\xd58C10\xe7' + \
            b'\x1ez+\xc8\x14\rK|3\x9a\x9b\xc1\xc1\xc8\xc5\xfeZHD\x1b\x87\x9d$\xd9"}'
        self.assertEqual(utils.twoping_checksum(data), 0x4a06)

    def test_twoping_checksum_packet(self):
        data = bytearray(
            b'\x32\x50\x8d\x3b\x00\x00\x00\x00\xb0\x06\x00\x3b\x00\x00\x00\x06\x00\x00\x00\x00\xa0\x0a\x00' +
            b'\x08\x00\x01\x00\x00\x00\x00\xa0\x01\x00\x08\x00\x01\x00\x00\x00\x00\xa0\x02\x00\x08\x00\x01' +
            b'\x00\x00\x00\x00\xb0\x02'
        )
        data[2] = 0
        data[3] = 0
        self.assertEqual(utils.twoping_checksum(data), 0x8d3b)

    def test_twoping_checksum_iter(self):
        i = 65535
        for x in range(256):
            for y in range(256):
                data = bytes([x, y])
                checksum = utils.twoping_checksum(data)
                self.assertEqual(checksum, i)
                i = i - 1
                if i == 0:
                    i = 65535


if __name__ == '__main__':
    unittest.main()
