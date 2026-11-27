# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Roberto Locatelli
"""0.14.1: what the whole suite found when it first ran on macOS and Windows (27/11/2026).

An IPv4 literal is read by the package's own inet_aton, not by the system's: on Windows socket.inet_aton (inet_addr)
refuses every spelling of 255.255.255.255, so `https://4294967295/a.crl` was taken for a NAME, resolved and connected
to (test_sentry_20261120, Windows, 0.14.1 before this change)."""
import ipaddress
import os
import random
import socket
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from omega_evidence import _crl_fetch as C  # noqa: E402

BCAST = ipaddress.IPv4Address("255.255.255.255")


def _windows_inet_aton(h):
    """socket.inet_aton as Windows answers it: what inet_addr reads, but INADDR_NONE (255.255.255.255) is an error"""
    b = _real_inet_aton(h)
    if b == b"\xff\xff\xff\xff":
        raise OSError("illegal IP address string passed to inet_aton")
    return b


_real_inet_aton = socket.inet_aton


class Ipv4LiteralOnEverySystem(unittest.TestCase):
    TABLE = {"4294967295": BCAST, "0xffffffff": BCAST, "0XFFFFFFFF": BCAST, "0377.0377.0377.0377": BCAST,
             "255.255.255.255": BCAST, "255.16777215": BCAST, "255.255.65535": BCAST, "127.1": "127.0.0.1",
             "2130706433": "127.0.0.1", "0x7f000001": "127.0.0.1", "0177.0.0.1": "127.0.0.1", "0": "0.0.0.0",
             "10.0x10.020.1": "10.16.16.1"}
    NAMES = ["", "0x", "0x.1", "08", "1..2", "256.1", "1.2.3.256", "1.2.65536", "4294967296", "0x100000000",
             "1.2.3.4.5", "0xg", "example.org", "1e3"]

    def test_the_table_is_read_the_same_here(self):
        for h, want in self.TABLE.items():
            self.assertEqual(C.address_of(h), ipaddress.IPv4Address(want), h)
        for h in self.NAMES:
            self.assertIsNone(C.address_of(h), h)

    def test_a_system_inet_aton_that_refuses_the_broadcast_does_not_change_the_reading(self):
        """fails on 0.14.1 before this change on every system: with socket.inet_aton answering as on Windows, the
        spellings of 255.255.255.255 were names"""
        with mock.patch.object(socket, "inet_aton", _windows_inet_aton):
            for h in ("4294967295", "0xffffffff", "255.255.255.255", "0377.0377.0377.0377"):
                self.assertEqual(C.address_of(h), BCAST, h)
                self.assertIsNotNone(C.why_not_public(C.address_of(h)), h)

    @unittest.skipUnless(sys.platform.startswith("linux"), "the reference is glibc's inet_aton, found on Linux only")
    def test_generated_strings_read_as_glibc_reads_them(self):
        rng = random.Random(20261127)
        alphabet = "0123456789xXabcdefg."
        n = 0
        for _ in range(100000):
            h = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 14)))
            try:
                ref = ipaddress.IPv4Address(_real_inet_aton(h))
            except OSError:
                ref = None
            self.assertEqual(C._inet_aton(h), ref, repr(h))
            n += ref is not None
        self.assertGreater(n, 1000)   # the generator reaches addresses, not only refusals


class OwnerOnlyKeyFile(unittest.TestCase):
    """The ML-DSA-65 key file is owner-only where the folder lets others read (POSIX: umask 022; Windows: the folder
    grants BUILTIN\\Users read, inherited by what is made in it). The positive control: a file made the ordinary way
    in the same folder is NOT owner-only by the same check. On 0.14.0 the key file on Windows kept the folder's entries."""

    def test_key_file_owner_only_and_an_ordinary_file_not(self):
        import tempfile
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import _ogni_sistema as OS
        from omega_evidence.pqbackends import mldsa
        with tempfile.TemporaryDirectory() as d:
            if OS.WINDOWS:
                subprocess.run(["icacls", d, "/grant", "*S-1-5-32-545:(OI)(CI)R"], check=True, capture_output=True)
            plain = os.path.join(d, "plain")
            old = os.umask(0o022) if not OS.WINDOWS else None
            try:
                open(plain, "wb").close()
            finally:
                if old is not None:
                    os.umask(old)
            self.assertNotEqual(OS.owner_only_problems(plain), [])          # the check can fail
            if not mldsa.available():
                self.skipTest("cryptography >= 48 (ML-DSA) absent: no key file to make")
            kf = os.path.join(d, "pq.key")
            mldsa.MlDsaFileSigner.keygen(kf)
            self.assertEqual(OS.owner_only_problems(kf), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
