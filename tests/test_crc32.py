import hmac
import unittest

from . import _test_module_init
from twoping import crc32


class TestCRC32(unittest.TestCase):
    def test_crc32(self):
        c = crc32.new(b"Data to hash")
        self.assertEqual(c.digest(), b"\x44\x9e\x0a\x5c")

    def test_hmac(self):
        h = hmac.new(b"Secret key", b"Data to hash", crc32)
        self.assertEqual(h.digest(), b"\x3c\xe1\xb6\xb9")

    def test_update(self):
        c = crc32.new()
        c.update(b"Data to hash")
        self.assertEqual(c.digest(), b"\x44\x9e\x0a\x5c")

    def test_hexdigest(self):
        c = crc32.new(b"Data to hash")
        self.assertEqual(c.hexdigest(), "449e0a5c")

    def test_clear(self):
        c = crc32.new(b"Data to hash")
        c.clear()
        self.assertEqual(c.digest(), b"\x00\x00\x00\x00")

    def test_zero_padding(self):
        c = crc32.new(b"jade")
        self.assertEqual(c.digest(), b"\x00\x83\x52\x18")

    def test_module_init(self):
        self.assertTrue(_test_module_init(crc32))
