#!/usr/bin/env python

import logging
from sys import argv
from time import sleep

from daemonize import Daemonize

logging.basicConfig(level=logging.DEBUG)

pid = argv[1]


def main():
    while True:
        sleep(5)

daemon = Daemonize(app="test_app", pid=pid, action=main)
daemon.start()
