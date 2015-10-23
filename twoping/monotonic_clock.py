#!/usr/bin/env python

import sys


class MonotonicClock():
    def __init__(self):
        if self.try_monotonic_clock():
            return

        import time
        if sys.platform in ('win32', 'cygwin'):
            self.clock = time.clock
            self.clock_name = 'time_clock'
            self.is_monotonic = False
        else:
            self.clock = time.time
            self.clock_name = 'time_time'
            self.is_monotonic = False

    def try_monotonic_clock(self):
        import ctypes
        import ctypes.util

        # https://github.com/ThomasHabets/monotonic_clock
        found_library = ctypes.util.find_library('monotonic_clock')
        if found_library is None:
            return False
        try:
            monotonic_clock = ctypes.cdll.LoadLibrary(found_library)
        except OSError:
            return False

        is_monotonic = monotonic_clock.monotonic_clock_is_monotonic
        is_monotonic.restype = ctypes.c_bool
        self.clock = monotonic_clock.clock_get_dbl
        self.clock.restype = ctypes.c_double
        self.is_monotonic = is_monotonic()
        self.clock_name = ctypes.c_char_p.in_dll(monotonic_clock, 'monotonic_clock_name').value
        return True
