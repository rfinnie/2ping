import locale
import logging
import pytest
import unittest
import unittest.mock

from . import _test_module_init
from twoping import args, cli, utils


class TestCLI(unittest.TestCase):
    bind_addresses = ["127.0.0.1"]
    port = None
    logger = None
    class_args = None

    def setUp(self):
        self.logger = logging.getLogger()
        self.logger.level = logging.DEBUG

    def _client(self, test_flags=None, test_positionals=None, test_stats=True, pairs=1):
        if self.port is None:
            port = -1
        else:
            port = self.port

        flag_args = ["--debug"]
        if self.class_args is not None:
            flag_args += self.class_args
        if test_flags is not None:
            flag_args += test_flags

        positional_args = []
        if test_positionals is not None:
            positional_args += test_positionals

        if "--loopback" not in flag_args:
            flag_args += ["--listen", "--port={}".format(port)]
            for bind_address in self.bind_addresses:
                flag_args.append("--interface-address={}".format(bind_address))
                positional_args.append(bind_address)
        if ("--adaptive" not in flag_args) and ("--flood" not in flag_args):
            flag_args.append("--count=1")
        if not ("--count=1" in flag_args):
            flag_args.append("--interval=5")
        all_args = ["2ping"] + flag_args + positional_args
        self.logger.info("Passed arguments: {}".format(all_args))

        p = cli.TwoPing(args.parse_args(all_args))
        self.logger.info("Parsed arguments: {}".format(p.args))
        self.assertEqual(p.run(), 0)

        for sock_class in p.sock_classes:
            self.assertTrue(sock_class.closed)

        self.assertEqual(len(p.sock_classes), (pairs * 2))
        client_sock_classes = [
            sock_class for sock_class in p.sock_classes if sock_class.is_client
        ]
        self.assertEqual(len(client_sock_classes), pairs)
        sock_class = client_sock_classes[0]

        if not test_stats:
            return sock_class

        self.assertEqual(sock_class.errors_received, 0)
        self.assertEqual(sock_class.lost_inbound, 0)
        self.assertEqual(sock_class.lost_outbound, 0)
        if p.args.count:
            self.assertEqual(sock_class.pings_transmitted, p.args.count)
            self.assertEqual(sock_class.pings_received, p.args.count)
        else:
            self.assertGreaterEqual(
                sock_class.pings_received / sock_class.pings_transmitted, 0.99
            )

        return sock_class

    def test_3way(self):
        sock_class = self._client([])
        self.assertEqual(sock_class.packets_transmitted, 2)
        self.assertEqual(sock_class.packets_received, 1)

    def test_3way_no(self):
        sock_class = self._client(["--no-3way"])
        self.assertEqual(sock_class.packets_transmitted, 1)
        self.assertEqual(sock_class.packets_received, 1)

    @pytest.mark.slow
    def test_adaptive(self):
        sock_class = self._client(["--adaptive", "--deadline=3"])
        self.assertGreaterEqual(sock_class.pings_transmitted, 100)

    @unittest.skipIf(isinstance(utils.AES, ImportError), "Crypto module required")
    def test_encrypt(self):
        self._client(
            ["--encrypt-method=hkdf-aes256-cbc", "--encrypt=S49HVbnJd3fBdDzdMVVw"]
        )

    @pytest.mark.slow
    def test_flood(self):
        sock_class = self._client(["--flood", "--deadline=3"])
        self.assertGreaterEqual(sock_class.pings_transmitted, 100)

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

    def test_invalid_hostname(self):
        with self.assertRaises(OSError):
            self._client([], ["xGkKWDDMnZxCD4XchMnK."])

    def test_monotonic_clock(self):
        self._client(["--send-monotonic-clock"])

    def test_notice(self):
        self._client(["--notice=Notice text"])

    @unittest.skipUnless(
        (locale.getlocale()[1] == "UTF-8"), "UTF-8 environment required"
    )
    def test_notice_utf8(self):
        self._client(["--notice=UTF-8 \u2603"])

    @pytest.mark.slow
    def test_packet_loss(self):
        # There is a small but non-zero chance that packet loss will prevent
        # any investigation replies from getting back to the client sock
        # between the 10 and 15 second mark, causing a test failure.
        # There's an even more minisculely small chance no simulated losses
        # will occur within the test period.
        sock_class = self._client(
            ["--flood", "--deadline=15", "--packet-loss=25"], test_stats=False
        )
        self.assertGreaterEqual(sock_class.pings_transmitted, 100)
        self.assertEqual(sock_class.errors_received, 0)
        self.assertGreater(sock_class.lost_inbound, 0)
        self.assertGreater(sock_class.lost_outbound, 0)

    def test_random(self):
        self._client(["--send-random=32"])

    def test_time(self):
        self._client(["--send-time"])

    def test_module_init(self):
        self.assertTrue(_test_module_init(cli))


class TestCLIInet(TestCLI):
    def test_srv_addresses(self):
        self.bind_addresses = []
        with unittest.mock.patch(
            "twoping.cli.TwoPing.get_srv_hosts", return_value=[("127.0.0.1", -1)]
        ):
            self._client(
                ["--interface-address=127.0.0.1", "--srv"], ["pssPCPkc3XlMTDZhclPV."]
            )


@unittest.skipUnless(hasattr(cli.socket, "AF_UNIX"), "UNIX environment required")
class TestCLILoopback(TestCLI):
    class_args = ["--loopback"]

    def test_loopback_pairs(self):
        self._client(["--loopback-pairs=3"], pairs=3)
