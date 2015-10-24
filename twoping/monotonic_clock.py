#!/usr/bin/env python

# Monotonic clock
# Copyright (C) 2015 Ryan Finnie
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

from __future__ import print_function, division
import sys
import time
import ctypes
import ctypes.util


class GettimeMonotonicCounter():
    adjustable = False
    implementation = None
    monotonic = True
    resolution = 0.0

    libraries = ('c',)

    class timespec_long(ctypes.Structure):
        _fields_ = (
            ('tv_sec', ctypes.c_long),
            ('tv_nsec', ctypes.c_long),
        )

    class timespec_int(ctypes.Structure):
        _fields_ = (
            ('tv_sec', ctypes.c_int),
            ('tv_nsec', ctypes.c_long),
        )

    def __init__(self):
        if not hasattr(self, 'clocks'):
            raise NotImplementedError()

        # We need to know the size of time_t, but can only reliably figure
        # it out in Python 2.7.
        try:
            import sysconfig
        except ImportError:
            raise RuntimeError('Cannot figure out timespec struct')
        sizeof_time_t = sysconfig.get_config_var('SIZEOF_TIME_T')
        sizeof_long = sysconfig.get_config_var('SIZEOF_LONG')
        sizeof_int = sysconfig.get_config_var('SIZEOF_INT')
        if sizeof_time_t == sizeof_long:
            self.timespec = self.timespec_long
        elif sizeof_time_t == sizeof_int:
            self.timespec = self.timespec_int
        else:
            raise RuntimeError('Cannot figure out timespec struct')

        self.clock_gettime = None
        for library_name in self.libraries:
            library_location = ctypes.util.find_library(library_name)
            if library_location is None:
                continue
            try:
                dll = ctypes.CDLL(library_location)
            except OSError:
                continue
            try:
                self.clock_gettime = dll.clock_gettime
            except AttributeError:
                continue
            break
        if self.clock_gettime is None:
            raise RuntimeError(
                'Cannot find suitable library for clock_gettime'
            )

        clock_getres = dll.clock_getres
        self.clock_id = None
        for (clock_id, clock_name, clock_monotonic) in self.clocks:
            res = self.timespec()
            if clock_getres(clock_id, ctypes.pointer(res)) != 0:
                continue
            self.resolution = res.tv_sec + (res.tv_nsec / 1e09)
            self.clock_id = clock_id
            self.implementation = 'clock_gettime(%s)' % clock_name
            self.monotonic = clock_monotonic
            break
        if self.clock_id is None:
            raise RuntimeError(
                'Cannot find suitable clock for clock_gettime'
            )

    def clock(self):
        tp = self.timespec()
        self.clock_gettime(self.clock_id, ctypes.pointer(tp))
        return tp.tv_sec + (tp.tv_nsec / 1e09)


class LinuxMonotonicCounter(GettimeMonotonicCounter):
    # http://linux.die.net/man/3/clock_gettime
    libraries = ('rt', 'c')
    clocks = (
        (4, 'CLOCK_MONOTONIC_RAW', True),
        (1, 'CLOCK_MONOTONIC', True),
        (0, 'CLOCK_REALTIME', False),
    )


class FreeBSDMonotonicCounter(GettimeMonotonicCounter):
    # https://www.freebsd.org/cgi/man.cgi?query=clock_gettime
    clocks = (
        (11, 'CLOCK_MONOTONIC_PRECISE', True),
        (4, 'CLOCK_MONOTONIC', True),
        (9, 'CLOCK_REALTIME_PRECISE', False),
        (0, 'CLOCK_REALTIME', False),
    )


class BSDMonotonicCounter(GettimeMonotonicCounter):
    # http://www.openbsd.org/cgi-bin/man.cgi/OpenBSD-current/man2/clock_gettime.2
    # https://www.daemon-systems.org/man/clock_gettime.2.html
    clocks = (
        (3, 'CLOCK_MONOTONIC', True),
        (0, 'CLOCK_REALTIME', False),
    )


class DarwinMonotonicCounter():
    # https://developer.apple.com/library/mac/qa/qa1398/
    adjustable = False
    implementation = 'mach_absolute_time()'
    monotonic = True
    resolution = 1e-09

    timebase = 0.0

    class mach_timebase_info_data_t(ctypes.Structure):
        _fields_ = (
            ('numer', ctypes.c_uint32),
            ('denom', ctypes.c_uint32),
        )

    def __init__(self):
        library = ctypes.util.find_library('c')
        dll = ctypes.CDLL(library)
        self.mach_absolute_time = dll.mach_absolute_time
        self.mach_absolute_time.restype = ctypes.c_uint64

        sTimebaseInfo = self.mach_timebase_info_data_t()
        dll.mach_timebase_info(ctypes.byref(sTimebaseInfo))
        self.timebase = float(sTimebaseInfo.numer) / sTimebaseInfo.denom

    def clock(self):
        return self.mach_absolute_time() * self.timebase / 1e09


class Win32MonotonicCounter():
    # https://msdn.microsoft.com/en-gb/library/windows/desktop/dn553408.aspx
    adjustable = False
    implementation = 'QueryPerformanceCounter()'
    monotonic = True
    resolution = 0.0

    LARGE_INTEGER = ctypes.c_int64
    BOOL = ctypes.c_int
    frequency = 0.0

    def __init__(self):
        dll = ctypes.windll.kernel32
        self.QueryPerformanceCounter = dll.QueryPerformanceCounter
        self.QueryPerformanceCounter.restype = self.BOOL

        QueryPerformanceFrequency = dll.QueryPerformanceFrequency
        QueryPerformanceFrequency.restype = self.BOOL
        frequency = self.LARGE_INTEGER()
        QueryPerformanceFrequency(ctypes.byref(frequency))
        self.frequency = float(frequency.value)
        self.resolution = 1.0 / self.frequency

    def clock(self):
        count = self.LARGE_INTEGER()
        self.QueryPerformanceCounter(ctypes.byref(count))
        return count.value / self.frequency


class SystemCounter():
    adjustable = True
    implementation = 'time()'
    monotonic = False
    resolution = 1.0

    def clock(self):
        return time.time()


class SimpleNamespace():
    def __init__(self, **kwargs):
        for (k, v) in kwargs.items():
            setattr(self, k, v)

    def __repr__(self):
        return 'namespace(%s)' % (', '.join(
            ['%s=%s' % (k, repr(v)) for (k, v) in self.__dict__.items()]
        ))


try:
    if sys.platform.startswith('linux'):
        _counter = LinuxMonotonicCounter()
    elif sys.platform.startswith(('freebsd', 'dragonfly')):
        _counter = FreeBSDMonotonicCounter()
    elif 'bsd' in sys.platform:
        _counter = BSDMonotonicCounter()
    elif sys.platform.startswith('darwin'):
        _counter = DarwinMonotonicCounter()
    elif sys.platform.startswith(('win32', 'cygwin')):
        _counter = Win32MonotonicCounter()
    else:
        _counter = SystemCounter()
except RuntimeError:
    # Fall back to built-in counter as a last resort
    _counter = SystemCounter()

clock = _counter.clock


def get_clock_info(clock):
    if clock != 'clock':
        raise ValueError('unknown clock')
    return SimpleNamespace(
        adjustable=_counter.adjustable,
        implementation=_counter.implementation,
        monotonic=_counter.monotonic,
        resolution=_counter.resolution,
    )


if __name__ == '__main__':
    print(get_clock_info('clock'))
    for _ in range(5):
        print('%0.050f' % clock())
