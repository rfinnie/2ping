#!/usr/bin/env python3

import unittest
import os
import subprocess
import time
import signal
import random
import locale
from twoping import monotonic_clock

try:
    from Crypto.Cipher import AES
    has_aes = True
except ImportError:
    has_aes = False


@unittest.skipUnless(hasattr(os, 'fork'), 'CLI tests require os.fork()')
class BaseTestCLI(unittest.TestCase):
    bind_address = '127.0.0.1'
    port = None
    settle_time = 3
    child_pid = 0
    twoing_binary = '/usr/bin/2ping'
    listener_opts = []

    @classmethod
    def setUpClass(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        self.twoping_binary = os.path.join(os.path.split(dir_path)[0], '2ping')
        (self.child_pid, self.port) = self.fork_listener(self, self.listener_opts)

    @classmethod
    def tearDownClass(self):
        if self.child_pid:
            os.kill(self.child_pid, signal.SIGINT)

    def fork_listener(self, extra_opts=None):
        if self.port:
            port = self.port
        else:
            port = random.randint(49152, 65535)
        opts = [
            '2ping',
            '--listen',
            '--quiet',
            '--no-3way',
            '--interface-address={}'.format(self.bind_address),
            '--port={}'.format(port),
        ]
        if extra_opts:
            opts += extra_opts

        child_pid = os.fork()
        if child_pid == 0:
            devnull_f = open(os.devnull, 'r')
            os.dup2(devnull_f.fileno(), 0)
            os.dup2(devnull_f.fileno(), 1)
            os.dup2(devnull_f.fileno(), 2)
            os.execv(self.twoping_binary, opts)
        time.sleep(self.settle_time)
        return((child_pid, port))

    def run_listener_client(self, client_opts, listener_opts=None):
        if listener_opts is None:
            listener_opts = []
        client_base_opts = [
            self.twoping_binary,
            self.bind_address,
            '--port={}'.format(self.port),
            '--debug',
            '--nagios=1000,5%,1000,5%',
        ]
        if not (('--adaptive' in client_opts) or ('--flood' in client_opts)):
            client_base_opts.append('--count=1')
        if not ('--count=1' in client_opts):
            client_base_opts.append('--interval=5')
        try:
            subprocess.check_output(client_base_opts + client_opts)
        except subprocess.CalledProcessError as e:
            self.fail(e.output)


class TestCLIStandard(BaseTestCLI):
    def test_notice(self):
        self.run_listener_client(['--notice=Notice text'])

    @unittest.skipUnless(
        (
            locale.getlocale()[1] == 'UTF-8'
        ), 'UTF-8 environment required'
    )
    def test_notice_utf8(self):
        self.run_listener_client(['--notice=UTF-8 \u2603'])

    def test_random(self):
        self.run_listener_client(['--send-random=32'])

    def test_time(self):
        self.run_listener_client(['--send-time'])

    @unittest.skipUnless(monotonic_clock.get_clock_info('clock').monotonic, 'Monotonic clock required')
    def test_monotonic_clock(self):
        self.run_listener_client(['--send-monotonic-clock'])

    def test_adaptive(self):
        self.run_listener_client(['--adaptive', '--deadline=3'])

    def test_flood(self):
        self.run_listener_client(['--flood', '--deadline=3'])


class TestCLIHMACMD5(BaseTestCLI):
    listener_opts = ['--auth-digest=hmac-md5', '--auth=rBgRpBfRbF4DkwFQXncz']

    def test_hmac(self):
        self.run_listener_client(self.listener_opts)


class TestCLIHMACSHA1(BaseTestCLI):
    listener_opts = ['--auth-digest=hmac-sha1', '--auth=qnzTCJHnZXdrxRZ8JjQw']

    def test_hmac(self):
        self.run_listener_client(self.listener_opts)


class TestCLIHMACSHA256(BaseTestCLI):
    listener_opts = ['--auth-digest=hmac-sha256', '--auth=cc8G2Ssbq4WZRq7H7d5L']

    def test_hmac(self):
        self.run_listener_client(self.listener_opts)


class TestCLIHMACSHA512(BaseTestCLI):
    listener_opts = ['--auth-digest=hmac-sha512', '--auth=sjk3kqzcSV3XfHJWNstn']

    def test_hmac(self):
        self.run_listener_client(self.listener_opts)


class TestCLIHMACCRC32(BaseTestCLI):
    listener_opts = ['--auth-digest=hmac-crc32', '--auth=mc82kJwtXFlhqQSCKptQ']

    def test_hmac(self):
        self.run_listener_client(self.listener_opts)


@unittest.skipUnless(has_aes, 'PyCrypto required')
class TestCLIEncryptAES256(BaseTestCLI):
    listener_opts = ['--encrypt-method=hkdf-aes256-cbc', '--auth=S49HVbnJd3fBdDzdMVVw']

    def test_encrypt(self):
        self.run_listener_client(self.listener_opts)


if __name__ == '__main__':
    unittest.main()
