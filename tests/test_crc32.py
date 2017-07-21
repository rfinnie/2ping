#!/usr/bin/env python3

import unittest
from twoping import crc32
import hmac


class TestCRC32(unittest.TestCase):
    def test_crc32(self):
        c = crc32.new()
        c.update(b'Data to hash')
        self.assertEqual(c.digest(), b'\x44\x9e\x0a\x5c')

    def test_hmac(self):
        h = hmac.new(b'Secret key', b'Data to hash', crc32)
        self.assertEqual(h.digest(), b'\x3c\xe1\xb6\xb9')


if __name__ == '__main__':
    unittest.main()
