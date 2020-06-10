import locale
import unittest

from twoping import args, cli, packets, utils


class TestCLI(unittest.TestCase):
    bind_address = "127.0.0.1"
    port = None

    @classmethod
    def _client_print(self, *args, **kwargs):
        pass

    def _client(self, test_args):
        if self.port is None:
            port = utils.random.randint(49152, 65535)
        else:
            port = self.port
        base_args = [
            "2ping",
            self.bind_address,
            "--listen",
            "--interface-address={}".format(self.bind_address),
            "--port={}".format(port),
            "--debug",
            "--nagios=1000,5%,1000,5%",
        ]
        if not (("--adaptive" in test_args) or ("--flood" in test_args)):
            base_args.append("--count=1")
        if not ("--count=1" in test_args):
            base_args.append("--interval=5")
        cli_args = args.parse_args(base_args + test_args)
        p = cli.TwoPing(cli_args)
        p.print_out = self._client_print
        self.assertEqual(int(p.run()), 0)

    def test_adaptive(self):
        self._client(["--adaptive", "--deadline=3"])

    @unittest.skipIf(isinstance(packets.AES, ImportError), "PyCrypto required")
    def test_encrypt(self):
        self._client(
            ["--encrypt-method=hkdf-aes256-cbc", "--auth=S49HVbnJd3fBdDzdMVVw"]
        )

    def test_flood(self):
        self._client(["--flood", "--deadline=3"])

    def test_hmac_crc32(self):
        self._client(["--auth-digest=hmac-crc32", "--auth=mc82kJwtXFlhqQSCKptQ"])

    def test_hmac_md5(self):
        self._client(["--auth-digest=hmac-md5", "--auth=rBgRpBfRbF4DkwFQXncz"])

    def test_hmac_sha1(self):
        self._client(["--auth-digest=hmac-sha1", "--auth=qnzTCJHnZXdrxRZ8JjQw"])

    def test_hmac_sha256(self):
        self._client(["--auth-digest=hmac-sha256", "--auth=cc8G2Ssbq4WZRq7H7d5L"])

    def test_hmac_sha512(self):
        self._client(["--auth-digest=hmac-sha512", "--auth=sjk3kqzcSV3XfHJWNstn"])

    def test_monotonic_clock(self):
        self._client(["--send-monotonic-clock"])

    def test_notice(self):
        self._client(["--notice=Notice text"])

    @unittest.skipUnless(
        (locale.getlocale()[1] == "UTF-8"), "UTF-8 environment required"
    )
    def test_notice_utf8(self):
        self._client(["--notice=UTF-8 \u2603"])

    def test_random(self):
        self._client(["--send-random=32"])

    def test_time(self):
        self._client(["--send-time"])


if __name__ == "__main__":
    unittest.main()
