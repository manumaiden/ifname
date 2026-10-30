#!/usr/bin/env python3
"""Self-tests for ifname — synthetic sosreports only (invented PCI/MAC).

    python3 test_ifname.py
"""

import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ifname  # noqa: E402

DB = """P: /devices/pci0000:00/0000:00:03.0/0000:01:00.0/net/{iface}
E: SUBSYSTEM=net
E: INTERFACE={iface}
E: ID_NET_DRIVER=tg3
E: ID_NET_NAMING_SCHEME=rhel-9.0
E: ID_NET_NAME_MAC=enx02aabbccdd01
E: ID_NET_NAME_ONBOARD=eno1
E: ID_NET_NAME_PATH=enp1s0f0
E: ID_PATH=pci-0000:01:00.0
E: ID_NET_NAME=eno1
"""


class Sos:
    """Throwaway sosreport tree: Sos().add("proc/cmdline", "ro").run("-d")."""
    def __init__(self, iface="eno1"):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        self.add(str(ifname.UDEVADM_DB), DB.format(iface=iface))

    def add(self, rel, content):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if isinstance(content, bytes) else content.encode())
        return self

    def run(self, *args, target=None):
        r = subprocess.run([sys.executable, "-I", str(HERE / "ifname.py"),
                            str(target or self.root), "--no-color", *args],
                           capture_output=True, text=True, errors="replace")
        self._tmp.cleanup()
        return r


class SafeStream(unittest.TestCase):
    def write(self, text, color=True):
        buf = io.StringIO()
        ifname._SafeStream(buf, color).write(text)
        return buf.getvalue()

    def test_drops_foreign_sequences(self):
        evil = ("a\x1b]52;c;SGVsbG8=\x07b\x1b[2Jc\x9b31md\x1b[08me\r"
                "f‮g​h\x1b]0;title\x1b\\i")
        self.assertEqual(self.write(evil), "abc31mdefghi")

    def test_own_colors_only_with_color(self):
        s = f"{ifname.RED}x{ifname.RESET}"
        self.assertEqual(self.write(s), s)
        self.assertEqual(self.write(s, color=False), "x")


class Run(unittest.TestCase):
    def assertClean(self, r):
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_basic(self):
        r = Sos().run("-d")
        self.assertClean(r)
        self.assertIn("onboard", r.stdout)

    def test_escaping_symlink_refused(self):
        s = Sos()
        (s.root / "proc").mkdir()
        os.symlink("/etc/hostname", s.root / "proc/cmdline")
        r = s.run()
        self.assertEqual(r.returncode, 1)
        self.assertIn("point outside the sosreport", r.stderr)

    def test_dangling_ifcfg_link(self):
        s = Sos()
        d = s.root / "etc/sysconfig/network-scripts"
        d.mkdir(parents=True)
        os.symlink("../nowhere", d / "ifcfg-eth0")
        self.assertClean(s.run())

    def test_bad_cmdline(self):
        self.assertClean(Sos().add("proc/cmdline", b"ro net.ifnames=0 \xff\n").run())
        s = Sos()
        (s.root / "proc/cmdline").mkdir(parents=True)
        self.assertClean(s.run())

    def test_empty_prefix_is_unset(self):
        r = Sos().add("proc/cmdline", "ro net.ifnames.prefix=\n").run()
        self.assertClean(r)
        self.assertNotIn("prefixdevname active", r.stdout)

    def test_udev_rule_by_mac_beats_candidate(self):
        rule = ('SUBSYSTEM=="net", ACTION=="add", ATTR{address}=="02:aa:bb:cc:dd:01", '
                'NAME="enp1s0f0"\n')
        r = Sos(iface="enp1s0f0").add("etc/udev/rules.d/70-persistent-net.rules", rule).run()
        self.assertClean(r)
        self.assertIn("udev rule (70-persistent-net.rules)", r.stdout)
        self.assertIn("[NOTE] MISMATCH", r.stdout)

    def test_bare_dump_hint_no_color(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d, "udev.txt")
            f.write_text(DB.format(iface="eno1"))
            r = subprocess.run([sys.executable, "-I", str(HERE / "ifname.py"), str(f)],
                               capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("must be saved as", r.stderr)
        self.assertNotIn("\x1b", r.stderr)


if __name__ == "__main__":
    unittest.main()
