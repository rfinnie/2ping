# SPDX-PackageName: 2ping
# SPDX-PackageSupplier: Ryan Finnie <ryan@finnie.org>
# SPDX-PackageDownloadLocation: https://codeberg.org/rfinnie/2ping
# SPDX-FileCopyrightText: © 2010 Ryan Finnie <ryan@finnie.org>
# SPDX-License-Identifier: MPL-2.0

import unittest.mock


def _test_module_init(module, main_name="main"):
    with (
        unittest.mock.patch.object(module, main_name, return_value=0),
        unittest.mock.patch.object(module, "__name__", "__main__"),
        unittest.mock.patch.object(module.sys, "exit") as exit,
    ):
        module.module_init()
        return exit.call_args[0][0] == 0
