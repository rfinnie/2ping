import time
import unittest


class TestPython(unittest.TestCase):
    def test_monotonic(self):
        val1 = time.monotonic()
        val2 = time.monotonic()
        self.assertGreaterEqual(val2, val1)
