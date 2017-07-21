#!/usr/bin/env python3

import unittest
import os
import subprocess
import sys
import time
import signal
import random


class TestCLI(unittest.TestCase):
    bind_address = '127.0.0.1'
    port = None
    settle_time = 1
    child_pid = 0
    twoing_binary = '/usr/bin/2ping'

    @classmethod
    def setUpClass(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        self.twoping_binary = os.path.join(os.path.split(dir_path)[0], '2ping')

    def tearDown(self):
        if self.child_pid:
            os.kill(self.child_pid, signal.SIGINT)
        self.child_pid = 0

    def fork_listener(self, extra_opts=None):
        if self.port:
            port = self.port
        else:
            port = random.randint(49152, 65535)
        opts = ['2ping', '--listen', '--quiet', '--interface-address={}'.format(self.bind_address), '--port={}'.format(port)]
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
        (self.child_pid, port) = self.fork_listener(listener_opts)
        client_base_opts = [self.twoping_binary, self.bind_address, '--port={}'.format(port), '--debug', '--nagios=1000,1%,1000,1%']
        try:
            subprocess.check_output(client_base_opts + client_opts)
        except subprocess.CalledProcessError as e:
            self.fail(e.output)

    def test_notice(self):
        self.run_listener_client(['--count=1', '--notice=foo ☃'])

    def test_random(self):
        self.run_listener_client(['--count=1', '--send-random=32'])

    def test_time(self):
        self.run_listener_client(['--count=1', '--send-time'])

    def test_monotonic_clock(self):
        self.run_listener_client(['--count=1', '--send-monotonic-clock'])

    def test_adaptive(self):
        self.run_listener_client(['--adaptive', '--deadline=5'])

    def test_flood(self):
        self.run_listener_client(['--flood', '--deadline=5'])

    def test_hmac_md5(self):
        self.run_listener_client(
            ['--nagios=1000,5%,1000,5%', '--count=1', '--auth-digest=hmac-md5', '--auth=rBgRpBfRbF4DkwFQXncz'],
            ['--auth-digest=hmac-md5', '--auth=rBgRpBfRbF4DkwFQXncz']
        )

    def test_hmac_sha1(self):
        self.run_listener_client(
            ['--nagios=1000,5%,1000,5%', '--count=1', '--auth-digest=hmac-sha1', '--auth=qnzTCJHnZXdrxRZ8JjQw'],
            ['--auth-digest=hmac-sha1', '--auth=qnzTCJHnZXdrxRZ8JjQw']
        )

    def test_hmac_sha256(self):
        self.run_listener_client(
            ['--nagios=1000,5%,1000,5%', '--count=1', '--auth-digest=hmac-sha256', '--auth=cc8G2Ssbq4WZRq7H7d5L'],
            ['--auth-digest=hmac-sha256', '--auth=cc8G2Ssbq4WZRq7H7d5L']
        )

    def test_hmac_sha512(self):
        self.run_listener_client(
            ['--nagios=1000,5%,1000,5%', '--count=1', '--auth-digest=hmac-sha512', '--auth=sjk3kqzcSV3XfHJWNstn'],
            ['--auth-digest=hmac-sha512', '--auth=sjk3kqzcSV3XfHJWNstn']
        )

    def test_hmac_crc32(self):
        self.run_listener_client(
            ['--nagios=1000,5%,1000,5%', '--count=1', '--auth-digest=hmac-crc32', '--auth=mc82kJwtXFlhqQSCKptQ'],
            ['--auth-digest=hmac-crc32', '--auth=mc82kJwtXFlhqQSCKptQ']
        )


if __name__ == '__main__':
    unittest.main()
