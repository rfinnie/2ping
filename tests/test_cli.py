import locale
import os
import random
import signal
import sys
import time
import unittest
import uuid

from twoping import args, cli, packets


@unittest.skipUnless(hasattr(os, "fork"), "CLI tests require os.fork()")
class BaseTestCLI(unittest.TestCase):
    bind_address = "127.0.0.1"
    port = None
    child_pid = 0
    listener_opts = []
    canary_filename = None
    canary_timeout = 10.0

    @classmethod
    def setUpClass(self):
        (self.child_pid, self.port) = self.fork_listener(self, self.listener_opts)

    @classmethod
    def tearDownClass(self):
        if self.child_pid:
            os.kill(self.child_pid, signal.SIGINT)

    @classmethod
    def listener_print(self, *args, **kwargs):
        pass

    @classmethod
    def listener_client_print(self, *args, **kwargs):
        pass

    @classmethod
    def listener_ready(self):
        with open(self.canary_filename, "w"):
            pass

    def fork_listener(self, extra_opts=None):
        self.canary_filename = os.path.join("/tmp", str(uuid.uuid4()))
        if self.port:
            port = self.port
        else:
            port = random.randint(49152, 65535)
        opts = [
            "2ping",
            "--listen",
            "--quiet",
            "--no-3way",
            "--interface-address={}".format(self.bind_address),
            "--port={}".format(port),
        ]
        if extra_opts:
            opts += extra_opts

        child_pid = os.fork()
        if child_pid == 0:
            cli_args = args.parse_args(opts)
            p = cli.TwoPing(cli_args)
            p.print_out = self.listener_print
            p.ready = self.listener_ready
            sys.exit(int(p.run()))

        begin_wait = time.monotonic()
        found_canary = False
        while time.monotonic() < begin_wait + self.canary_timeout:
            if os.path.exists(self.canary_filename):
                os.remove(self.canary_filename)
                found_canary = True
                break
            time.sleep(0.25)
        if not found_canary:
            raise RuntimeError("Did not find listener start canary")

        return (child_pid, port)

    def run_listener_client(self, client_opts, listener_opts=None):
        if listener_opts is None:
            listener_opts = []
        client_base_opts = [
            "2ping",
            self.bind_address,
            "--port={}".format(self.port),
            "--debug",
            "--nagios=1000,5%,1000,5%",
        ]
        if not (("--adaptive" in client_opts) or ("--flood" in client_opts)):
            client_base_opts.append("--count=1")
        if not ("--count=1" in client_opts):
            client_base_opts.append("--interval=5")
        cli_args = args.parse_args(client_base_opts + client_opts)
        p = cli.TwoPing(cli_args)
        p.print_out = self.listener_client_print
        self.assertEqual(int(p.run()), 0)


class TestCLIStandard(BaseTestCLI):
    def test_notice(self):
        self.run_listener_client(["--notice=Notice text"])

    @unittest.skipUnless(
        (locale.getlocale()[1] == "UTF-8"), "UTF-8 environment required"
    )
    def test_notice_utf8(self):
        self.run_listener_client(["--notice=UTF-8 \u2603"])

    def test_random(self):
        self.run_listener_client(["--send-random=32"])

    def test_time(self):
        self.run_listener_client(["--send-time"])

    def test_monotonic_clock(self):
        self.run_listener_client(["--send-monotonic-clock"])

    def test_adaptive(self):
        self.run_listener_client(["--adaptive", "--deadline=3"])

    def test_flood(self):
        self.run_listener_client(["--flood", "--deadline=3"])


class TestCLIHMACMD5(BaseTestCLI):
    listener_opts = ["--auth-digest=hmac-md5", "--auth=rBgRpBfRbF4DkwFQXncz"]

    def test_hmac(self):
        self.run_listener_client(self.listener_opts)


class TestCLIHMACSHA1(BaseTestCLI):
    listener_opts = ["--auth-digest=hmac-sha1", "--auth=qnzTCJHnZXdrxRZ8JjQw"]

    def test_hmac(self):
        self.run_listener_client(self.listener_opts)


class TestCLIHMACSHA256(BaseTestCLI):
    listener_opts = ["--auth-digest=hmac-sha256", "--auth=cc8G2Ssbq4WZRq7H7d5L"]

    def test_hmac(self):
        self.run_listener_client(self.listener_opts)


class TestCLIHMACSHA512(BaseTestCLI):
    listener_opts = ["--auth-digest=hmac-sha512", "--auth=sjk3kqzcSV3XfHJWNstn"]

    def test_hmac(self):
        self.run_listener_client(self.listener_opts)


class TestCLIHMACCRC32(BaseTestCLI):
    listener_opts = ["--auth-digest=hmac-crc32", "--auth=mc82kJwtXFlhqQSCKptQ"]

    def test_hmac(self):
        self.run_listener_client(self.listener_opts)


@unittest.skipIf(isinstance(packets.AES, ImportError), "PyCrypto required")
class TestCLIEncryptAES256(BaseTestCLI):
    listener_opts = ["--encrypt-method=hkdf-aes256-cbc", "--auth=S49HVbnJd3fBdDzdMVVw"]

    def test_encrypt(self):
        self.run_listener_client(self.listener_opts)


if __name__ == "__main__":
    unittest.main()
