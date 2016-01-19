import unittest
import os
import pwd
import grp
import subprocess
import fcntl
import errno
import logging

logging.basicConfig(level=logging.DEBUG)

from tempfile import mkstemp
from time import sleep
from os.path import split
from daemonize import Daemonize

NOBODY_UID = pwd.getpwnam("nobody").pw_uid
if os.path.exists("/etc/debian_version"):
    NOBODY_GID = grp.getgrnam("nogroup").gr_gid
else:
    NOBODY_GID = grp.getgrnam("nobody").gr_gid


class DaemonTestCase(unittest.TestCase):
    def tearDown(self):
        try:
            with open(self.pidfile) as f:
                read_pid = f.read()
            if not read_pid:
                sleep(.1)
                return
            pid = int(read_pid)
            os.kill(pid, 15)
        except IOError as err:
            if err.errno == errno.ENOENT:
                pass
        except OSError as err:
            if err.errno == errno.ESRCH:
                pass
        sleep(.1)


class DaemonizeTest(DaemonTestCase):
    def setUp(self):
        self.pidfile = mkstemp()[1]
        os.system("python tests/daemon_sigterm.py %s" % self.pidfile)
        sleep(.1)

    def test_is_working(self):
        sleep(1)
        proc = subprocess.Popen("ps ax | awk '{print $1}' | grep `cat %s`" % self.pidfile,
                                shell=True, stdout=subprocess.PIPE)
        ps_pid = proc.communicate()[0].decode()
        with open(self.pidfile, "r") as pidfile:
            pid = pidfile.read()
        self.assertEqual("%s\n" % pid, ps_pid)

    def test_pidfile_presence(self):
        sleep(1)
        self.assertTrue(os.path.isfile(self.pidfile))


class LockingTest(DaemonTestCase):
    def setUp(self):
        self.pidfile = mkstemp()[1]
        print("\n    First daemonize process started")
        os.system("python tests/daemon_sigterm.py %s" % self.pidfile)
        sleep(.1)

    def test_locking(self):
        sleep(1)
        print("    Attempting to start second daemonize process [Expect ERROR log]")
        proc = subprocess.call(["python", "tests/daemon_sigterm.py", self.pidfile])
        self.assertEqual(proc, 1)


class KeepFDsTest(DaemonTestCase):
    def setUp(self):
        self.pidfile = mkstemp()[1]
        self.logfile = mkstemp()[1]
        os.system("python tests/daemon_keep_fds.py %s %s" % (self.pidfile, self.logfile))
        sleep(1)

    def tearDown(self):
        super(KeepFDsTest, self).tearDown()
        os.remove(self.logfile)
        sleep(.1)

    def test_keep_fds(self):
        log = open(self.logfile, "r").read()
        self.assertEqual(log, "Test\n")


class UidGidTest(DaemonTestCase):
    def setUp(self):
        self.expected = " ".join(map(str, [NOBODY_UID] * 2 + [NOBODY_GID] * 2))
        self.pidfile = mkstemp()[1]
        self.logfile = mkstemp()[1]

    def tearDown(self):
        os.remove(self.logfile)

    def test_uid_gid(self):
        # Skip test if user is not root
        if os.getuid() != 0:
            return True

        os.chown(self.logfile, NOBODY_UID, NOBODY_GID)

        os.system("python tests/daemon_uid_gid.py %s %s" % (self.pidfile, self.logfile))
        sleep(1)

        with open(self.logfile, "r") as f:
            self.assertEqual(f.read(), self.expected)
        self.assertFalse(os.access(self.pidfile, os.F_OK))

    def test_uid_gid_action(self):
        # Skip test if user is not root
        if os.getuid() != 0:
            return True

        os.chown(self.pidfile, NOBODY_UID, NOBODY_GID)

        os.system("python tests/daemon_uid_gid_action.py %s %s" % (self.pidfile, self.logfile))
        sleep(1)

        with open(self.logfile, "r") as f:
            self.assertEqual(f.read(), self.expected)


class PrivilegedActionTest(DaemonTestCase):
    def setUp(self):
        self.correct_log = """Privileged action.
Starting daemon.
Action.
Daemon exiting.
"""
        self.pidfile = mkstemp()[1]
        self.logfile = mkstemp()[1]
        os.system("python tests/daemon_privileged_action.py %s %s" % (self.pidfile, self.logfile))
        sleep(.1)

    def test_privileged_action(self):
        sleep(1)
        with open(self.logfile, "r") as contents:
            self.assertEqual(contents.read(), self.correct_log)


class ChdirTest(DaemonTestCase):
    def setUp(self):
        self.pidfile = mkstemp()[1]
        self.target = mkstemp()[1]
        base, file = split(self.target)

        os.system("python tests/daemon_chdir.py %s %s %s" % (self.pidfile, base, file))
        sleep(1)

    def test_chdir(self):
        log = open(self.target, "r").read()
        self.assertEqual(log, "test")

def sleep_forever():
    while True:
        logging.error('sleep_forever')
        sleep(1)


class NoExitTests(DaemonTestCase):

    def test_raise_no_write(self):
        self.pidfile = '/doesnotexist/pidfile'

        daemon = Daemonize(app='NoExitTest_RaiseNoWrite', pid=self.pidfile,
                           action=sleep_forever, raise_prior_to_fork=True)
        print("\n    Attempting to daemonize with inaccessable pidfile [Expect ERROR log]")
        with self.assertRaises(IOError):
            daemon.start()

    def test_raise_no_lock(self):
        self.pidfd, self.pidfile = mkstemp()

        try:
            fcntl.flock(self.pidfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except:
            logging.exception('Failed initial lock on pidfile: %s', self.pidfile)
            raise

        daemon = Daemonize(app='NoExitTest_RaiseNoLock', pid=self.pidfile,
                           action=sleep_forever, raise_prior_to_fork=True)
        print("\n    Attempting to daemonize with locked pidfile [Expect ERROR log]")
        with self.assertRaises(IOError):
            daemon.start()

    def test_parent_return(self):
        self.pidfile = mkstemp()[1]
        self.logfile = mkstemp()[1]

        logger = logging.getLogger(__name__)
        logger.setLevel(logging.DEBUG)
        logger.propagate = False
        fh = logging.FileHandler(self.logfile, "w")
        fh.setLevel(logging.DEBUG)
        logger.addHandler(fh)
        keep_fds = [fh.stream.fileno()]

        daemon = Daemonize(app='NoExitTest_ParentReturn', pid=self.pidfile,
                           keep_fds=keep_fds,
                           action=sleep_forever, return_in_parent=True)
        child_pid = daemon.start()
        sleep(1.0)
        try:
            with open(self.pidfile) as f:
                read_pid = f.read()
            pid = int(read_pid)
        except:
            logging.exception('child failed to write proper pidfile: %s', self.pidfile)
            raise
        # Make sure the pid we got back from start matches the pidfile
        self.assertEqual(child_pid, pid)
        # Kill -9 to avoid unittest framework getting control in child
        try:
            os.kill(pid, 9)
        except OSError as err:
            if err.errno == errno.ESRCH:
                self.fail('Child process was not running.')
            else:
                self.fail('Unexpected OSError errno: %d', err.errno)
        # And do cleanup of pidfile ourselves
        try:
            os.remove(self.pidfile)
        except OSError as err:
            if err.errno == errno.ENOENT:
                pass
            else:
                raise


if __name__ == '__main__':
    unittest.main(verbosity=2)
