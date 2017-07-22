#!/usr/bin/env python3

import unittest
from twoping import best_poller
import socket


class TestBestPoller(unittest.TestCase):
    def test_register(self):
        poller = best_poller.best_poller()
        s = socket.socket()
        poller.register(s)
        self.assertEqual(
            poller.f_dict[s.fileno()],
            s
        )
        s.close()

    def test_register_multiple(self):
        poller = best_poller.best_poller()
        s1 = socket.socket()
        s2 = socket.socket()
        poller.register(s1)
        poller.register(s2)
        self.assertEqual(
            (poller.f_dict[s1.fileno()], poller.f_dict[s2.fileno()]),
            (s1, s2)
        )
        s1.close()
        s2.close()

    def test_register_idempotent(self):
        poller = best_poller.best_poller()
        s = socket.socket()
        poller.register(s)
        poller.register(s)
        self.assertEqual(
            len(poller.f_dict),
            1
        )
        s.close()

    def test_available_pollers(self):
        self.assertTrue(len(best_poller.available_pollers()) > 0)

    def test_known_poller(self):
        self.assertTrue(isinstance(
            best_poller.best_poller(),
            (
                best_poller.EpollPoller,
                best_poller.KqueuePoller,
                best_poller.PollPoller,
                best_poller.SelectPoller,
            )
        ))


if __name__ == '__main__':
    unittest.main()
