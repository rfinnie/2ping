#!/usr/bin/env python3

import unittest
from twoping import monotonic_clock


class TestMonotonicClock(unittest.TestCase):
    def setUp(self):
        self.clock = monotonic_clock.clock
        self.clock_info = monotonic_clock.get_clock_info('clock')

    def test_clock(self):
        self.assertEqual(type(self.clock()), float)

    def test_monotonic(self):
        if not self.clock_info.monotonic:
            return
        time1 = self.clock()
        time2 = self.clock()
        self.assertTrue(time2 > time1)


if __name__ == '__main__':
    unittest.main()
