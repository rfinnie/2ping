# SPDX-PackageSummary: 2ping - A bi-directional ping utility
# SPDX-FileCopyrightText: Copyright (C) 2010-2025 Ryan Finnie
# SPDX-License-Identifier: MPL-2.0

import time
import unittest


class TestPython(unittest.TestCase):
    def test_monotonic(self):
        val1 = time.monotonic()
        val2 = time.monotonic()
        self.assertGreaterEqual(val2, val1)
