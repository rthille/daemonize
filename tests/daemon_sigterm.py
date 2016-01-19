#!/usr/bin/env python

from logging import basicConfig
from sys import argv
from time import sleep

from daemonize import Daemonize

basicConfig()

pid = argv[1]


def main():
    while True:
        sleep(5)

daemon = Daemonize(app="test_app", pid=pid, action=main)
daemon.start()
