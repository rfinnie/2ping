#!/usr/bin/env python3

import unittest

from twoping import utils


class TestUtils(unittest.TestCase):
    def test_twoping_checksum_hello(self):
        data = b'Hello World'
        self.assertEqual(utils.twoping_checksum(data), 0xAE31)

    def test_twoping_checksum_junk(self):
        data = (
            b'\x45\xc6\xca\x92\x10\x0e\xb1\xcf\x98\x88\x0b\x42\xc0\xf8\x58\xac\xd9\x81\x76\xc0\x45\x8c\x6f'
            b'\x04\x9c\x0e\x93\xb3\x49\x3d\x38\x6d\xb7\xd5\x86\xa7\x66\x2c\x32\x15\xd9\x7f\xad\x3e\x1a\xe0'
            b'\x39\x89\x4a\xdd\x0b\x28\xa0\x07\x61\x47\x54\xc6\x50\x04\x2d\x28\x4e\x48\x3c\x40\xc7\xdb\x82'
            b'\xfa\x0b\xab\x37\x6e\x23\x5e\x80\xab\xb9\xe5\x05\x14\xb1\xfc\x72\x54\x37\x8a\x66\xf2\x51\xa1'
            b'\x77\xda\xd5\x88\xd5\x38\x43\x31\x30\xe7\x1e\x7a\x2b\xc8\x14\x0d\x4b\x7c\x33\x9a\x9b\xc1\xc1'
            b'\xc8\xc5\xfe\x5a\x48\x44\x1b\x87\x9d\x24\xd9\x22\x7d'
        )
        self.assertEqual(utils.twoping_checksum(data), 0x4A06)

    def test_twoping_checksum_packet(self):
        data = bytearray(
            b'\x32\x50\x8d\x3b\x00\x00\x00\x00\xb0\x06\x00\x3b\x00\x00\x00\x06\x00\x00\x00\x00\xa0\x0a\x00'
            b'\x08\x00\x01\x00\x00\x00\x00\xa0\x01\x00\x08\x00\x01\x00\x00\x00\x00\xa0\x02\x00\x08\x00\x01'
            b'\x00\x00\x00\x00\xb0\x02'
        )
        data[2] = 0
        data[3] = 0
        self.assertEqual(utils.twoping_checksum(data), 0x8D3B)

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
