import time
import unittest


class Test2Ping(unittest.TestCase):
    def test_monotonic(self):
        val1 = time.monotonic()
        val2 = time.monotonic()
        self.assertGreater(val2, val1)
