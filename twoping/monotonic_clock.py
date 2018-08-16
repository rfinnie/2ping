#!/usr/bin/env python3

# Monotonic clock
# Copyright (C) 2010-2018 Ryan Finnie
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

import sys
import time
import types


class BuiltinMonotonicCounter():
    clock = None

    def __init__(self):
        # Unix + CLOCK_MONOTONIC_RAW
        if hasattr(time, 'clock_gettime') and hasattr(time, 'CLOCK_MONOTONIC_RAW'):
            self.info = time.get_clock_info('monotonic')
            self.info.implementation = 'clock_gettime(CLOCK_MONOTONIC_RAW)'

            def _clock():
                return time.clock_gettime(time.CLOCK_MONOTONIC_RAW)

            self.clock = _clock
            self.clock()
            return

        # All other platforms
        for mode in ('perf_counter', 'monotonic', 'clock'):
            try:
                self.info = time.get_clock_info(mode)
            except ValueError:
                continue
            if not self.info.monotonic:
                continue
            if self.info.resolution > 1e-06:
                continue
            self.clock = getattr(time, mode)
            self.clock()
            return

        raise NotImplementedError()


class SystemCounter():
    info = types.SimpleNamespace(
        adjustable=True,
        implementation='time()',
        monotonic=False,
        resolution=1.0,
    )

    def clock(self):
        return time.time()


try:
    _counter = BuiltinMonotonicCounter()
except RuntimeError:
    # Fall back to time.time() as a last resort
    _counter = SystemCounter()

clock = _counter.clock
monotonic = _counter.clock


def get_clock_info(clock):
    if clock not in ('clock', 'monotonic'):
        raise ValueError('unknown clock')
    return _counter.info


if __name__ == '__main__':
    if len(sys.argv) > 1:
        for _ in range(int(sys.argv[1])):
            print('{:.50f}'.format(clock()))
    else:
        print(get_clock_info('clock'))
        previous = 0.0
        for _ in range(10):
            current = clock()
            if current >= previous:
                print('{:.50f}'.format(current))
            else:
                print('{:.50f} (!!!)'.format(current))
