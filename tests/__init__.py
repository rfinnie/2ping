import unittest.mock


def _test_module_init(module, main_name="main"):
    with unittest.mock.patch.object(
        module, main_name, return_value=0
    ), unittest.mock.patch.object(
        module, "__name__", "__main__"
    ), unittest.mock.patch.object(
        module.sys, "exit"
    ) as exit:
        module.module_init()
        return exit.call_args[0][0] == 0
