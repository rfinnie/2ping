#!/usr/bin/env python3

import unittest
from twoping import monotonic_clock


clock = monotonic_clock.clock
clock_info = monotonic_clock.get_clock_info('clock')


class TestMonotonicClock(unittest.TestCase):
    def test_clock(self):
        self.assertEqual(type(clock()), float)

    @unittest.skipUnless(clock_info.monotonic, 'Monotonic clock required')
    def test_monotonic(self):
        time1 = clock()
        time2 = clock()
        self.assertGreaterEqual(time2, time1)


if __name__ == '__main__':
    unittest.main()
