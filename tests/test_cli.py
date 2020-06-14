import locale
import unittest
import unittest.mock

from . import _test_module_init
from twoping import args, cli, utils


class TestCLI(unittest.TestCase):
    bind_address = "127.0.0.1"
    port = None

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
        p.print_out = unittest.mock.Mock()
        self.assertEqual(p.run(), 0)

        for sock_class in p.sock_classes:
            self.assertTrue(sock_class.closed)

        self.assertEqual(len(p.sock_classes), 2)
        client_sock_classes = [
            sock_class for sock_class in p.sock_classes if sock_class.client_host
        ]
        self.assertEqual(len(client_sock_classes), 1)
        sock_class = client_sock_classes[0]

        self.assertEqual(sock_class.errors_received, 0)
        self.assertEqual(sock_class.lost_inbound, 0)
        self.assertEqual(sock_class.lost_outbound, 0)
        if cli_args.count:
            self.assertEqual(sock_class.pings_transmitted, cli_args.count)
            self.assertEqual(sock_class.pings_received, cli_args.count)

        return sock_class

    def test_adaptive(self):
        sock_class = self._client(["--adaptive", "--deadline=3"])
        self.assertGreaterEqual(sock_class.pings_transmitted, 100)
        self.assertGreaterEqual(
            sock_class.pings_received / sock_class.pings_transmitted, 0.99
        )

    @unittest.skipIf(isinstance(utils.AES, ImportError), "PyCryptodome required")
    def test_encrypt(self):
        self._client(
            ["--encrypt-method=hkdf-aes256-cbc", "--auth=S49HVbnJd3fBdDzdMVVw"]
        )

    def test_flood(self):
        sock_class = self._client(["--flood", "--deadline=3"])
        self.assertGreaterEqual(sock_class.pings_transmitted, 100)
        self.assertGreaterEqual(
            sock_class.pings_received / sock_class.pings_transmitted, 0.99
        )

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

    def test_module_init(self):
        self.assertTrue(_test_module_init(cli))


if __name__ == "__main__":
    unittest.main()
