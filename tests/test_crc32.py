#!/usr/bin/env python

import unittest
from twoping import crc32
import hmac


class TestCRC32(unittest.TestCase):
    def test_crc32(self):
        c = crc32.new()
        c.update('Data to hash')
        self.assertEqual(bytearray(c.digest()), bytearray(b'\x44\x9e\x0a\x5c'))

    def test_hmac(self):
        h = hmac.new('Secret key', 'Data to hash', crc32)
        self.assertEqual(bytearray(h.digest()), bytearray(b'\x3c\xe1\xb6\xb9'))


if __name__ == '__main__':
    unittest.main()
