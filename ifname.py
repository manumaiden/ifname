#!/usr/bin/env python3
# DESC: Diagnose network interface renaming from a systemd udev database (e.g. a sosreport).
"""
ifname - Analyze network interface renaming from a sosreport udev database.

Run from the sosreport root directory:
    python3 ifname.py
    python3 ifname.py --detail

Or pass the sosreport root (or the udev DB file directly) as an argument:
    python3 ifname.py /path/to/sosreport-xxx -d
"""

from __future__ import annotations  # "str | None" hints on Python 3.9 (RHEL 9)

import argparse
import configparser
import os
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------

RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[31m"
GREEN   = "\033[32m"
YELLOW  = "\033[33m"
BLUE    = "\033[34m"
MAGENTA = "\033[35m"
CYAN    = "\033[36m"
WHITE   = "\033[97m"
BG_BLUE = "\033[44m"

# Any terminal escape sequence: CSI (ESC [ … final byte), OSC (ESC ] … BEL/ST)
# or a two-byte ESC x. Only our own colors (_OWN_SGR, exact match) may reach the terminal.
_TERM_ESC_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)?|[@-Z\\-_])")
_OWN_SGR = {RESET, BOLD, DIM, RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN, WHITE, BG_BLUE}
# C0 (except \t \n), DEL, C1 (8-bit CSI/OSC), invisible/bidi format chars (Trojan Source)
_CTRL_RE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f​-‏‪-‮⁠-⁤⁦-⁩﻿]")


class _SafeStream:
    """Stdout wrapper applied to every run: sosreport content (udev properties,
    rule files) is untrusted, so OSC (clipboard, title), cursor/erase sequences,
    any SGR that is not one of ours (concealed, reverse, blink, …) and C0/C1
    control characters (\r, BEL, 8-bit CSI/OSC, …) are dropped.
    color=False (--no-color or no TTY) drops our SGR colors as well."""
    def __init__(self, stream, color: bool = True):
        self._s = stream
        self._color = color

    def write(self, text: str) -> int:
        out, pos = [], 0
        for m in _TERM_ESC_RE.finditer(text):
            out.append(_CTRL_RE.sub("", text[pos:m.start()]))
            if self._color and m.group() in _OWN_SGR:
                out.append(m.group())
            pos = m.end()
        out.append(_CTRL_RE.sub("", text[pos:]))
        return self._s.write("".join(out))

    def flush(self) -> None:
        self._s.flush()

    def isatty(self) -> bool:
        return False

    def fileno(self) -> int:
        return self._s.fileno()


__version__    = "1.4"
__build_date__ = "30102026"

UDEVADM_DB = Path("sos_commands/devices/udevadm_info_--export-db")

# systemd naming priority: first match wins (highest to lowest priority)
SYSTEMD_PRIO = [
    ("ID_NET_NAME_FROM_DATABASE", "database/hwdb"),
    ("ID_NET_NAME_ONBOARD",       "onboard"),
    ("ID_NET_NAME_SLOT",          "slot"),
    ("ID_NET_NAME_PATH",          "path"),
    ("ID_NET_NAME_MAC",           "mac"),
]

# biosdevname name patterns: em<n> (onboard), p<n>p<n> (PCIe slot)
RE_BIOSDEVNAME = re.compile(r"^(em\d+|p\d+p\d+)$")

# Match only PCI-rooted net devices (same filter as the awk one-liner)
RE_PCI_NET = re.compile(r"^/devices/pci[^/].*?/net/")

# PCI bus address embedded in ID_PATH, e.g. "pci-0000:01:00.0" -> "0000:01:00.0"
RE_PCI_PATH = re.compile(r"pci-((?:[0-9a-f]{4}:)?[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f])")

# Udev rule: NAME="..." assignment (single =, not ==)
RE_NAME_ASSIGN = re.compile(r'\bNAME="[^"]+"')

# Udev rule: tokens that identify a network device rule
RE_NET_INDICATOR = re.compile(
    r'(?:SUBSYSTEM=="net"|KERNEL=="(?:eth|en)[^"]*"|ATTR\{address\})', re.I
)

# Udev rule: NAME="..." value and ATTR{address}=="..." value, for rename-map lookups
RE_NAME_VALUE = re.compile(r'\bNAME="([^"]+)"')
RE_ATTR_ADDR = re.compile(r'ATTR\{address\}=="([0-9a-fA-F:]+)"')

_LINK_DIRS = ("etc/systemd/network", "usr/lib/systemd/network")

# Default naming policy per RHEL major release: RHEL 7 renames in
# 80-net-name-slot.rules, RHEL 8+ via 80-net-setup-link.rules + the NamePolicy
# of 99-default.link (RHEL 8: no "keep"; RHEL 9/10: with "keep").
DEFAULT_POLICY = {
    7:  ("onboard → slot → path", "80-net-name-slot.rules, RHEL 7"),
    8:  ("kernel database onboard slot path", "default, 99-default.link"),
    9:  ("keep kernel database onboard slot path", "default, 99-default.link"),
    10: ("keep kernel database onboard slot path", "default, 99-default.link"),
}


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def section(title: str) -> None:
    bar = "═" * 72
    print(f"\n{BOLD}{BG_BLUE}{WHITE}{bar}{RESET}")
    print(f"{BOLD}{BG_BLUE}{WHITE}  [1] {title}{RESET}")
    print(f"{BOLD}{BG_BLUE}{WHITE}{bar}{RESET}")


def subsection(title: str) -> None:
    print(f"\n  {BOLD}{CYAN}{title.upper()}:{RESET}")


def ok(msg: str) -> None:
    print(f"    {GREEN}[OK]{RESET}   {msg}")


def warn(msg: str, *hints: str) -> None:
    print(f"    {YELLOW}[WARN]{RESET} {msg}")
    for h in hints:
        if h:
            print(f"           {DIM}↳ {h}{RESET}")


def note(msg: str) -> None:
    print(f"    {MAGENTA}[NOTE]{RESET} {msg}")


def label(msg: str) -> None:
    print(f"    {BLUE}[INFO]{RESET} {msg}")


def kv(key: str, value: str) -> None:
    print(f"    {DIM}{key:<16}{RESET} {value}")


def tbl_header(*cols: tuple) -> None:
    print("    " + "  ".join(f"{h:<{w}}" for h, w in cols))
    print("    " + "  ".join("─" * w for _, w in cols))


# ---------------------------------------------------------------------------
# udev DB parsing
# ---------------------------------------------------------------------------

def parse_blocks(path: Path):
    """Yield one dict per udev block for PCI net devices."""
    for raw in re.split(r"\n{2,}", path.read_text(errors="replace")):
        block: dict[str, str] = {}
        for line in raw.splitlines():
            if line.startswith("P: "):
                block["P"] = line[3:]
            elif line.startswith("M: "):
                block["M"] = line[3:]
            elif line.startswith("E: ") and "=" in line[3:]:
                k, v = line[3:].split("=", 1)
                block[k] = v
        # only the net device itself — not child devices living under its
        # sysfs dir (e.g. r8169 LEDs: /net/enp7s0/enp7s0-0::lan, SUBSYSTEM=leds)
        if RE_PCI_NET.match(block.get("P", "")) and block.get("SUBSYSTEM", "net") == "net":
            yield block


def get_naming_scheme(blocks: list[dict]) -> str | None:
    """Return the first ID_NET_NAMING_SCHEME value among the parsed blocks, or None."""
    return next((b["ID_NET_NAMING_SCHEME"] for b in blocks if "ID_NET_NAMING_SCHEME" in b), None)


def naming_source(block: dict, prefix: str | None = None,
                  ctx: dict | None = None) -> tuple[str, str]:
    """Return (source_label, kind) for what actually produced the interface name.

    Matched against the real name, not just the first ID_NET_NAME_* candidate:
    75-net-description.rules always fills the candidates (also with biosdevname,
    udev rules or masked naming), and the mac policy is never used by default.
    ctx: {"rename_map", "link_names" {name: file}, "ifcfg_devices" {name: file}}.
    kind is one of candidate, udev, link, ifcfg, biosdevname, prefixdevname, kernel, unknown.
    """
    iface = block.get("INTERFACE", block.get("M", "?"))
    ctx = ctx or {}

    if prefix and re.match(rf"^{re.escape(prefix)}\d+$", iface):
        return f"prefixdevname [{prefix}<n>]", "prefixdevname"

    # a rule matching this NIC's MAC runs (70-*) before the naming policy (80-*),
    # so it wins even when it picks a name equal to another candidate
    rmap = ctx.get("rename_map") or {"by_mac": {}, "by_name": {}}
    hit = rmap["by_mac"].get(mac_from_block(block))
    if hit and hit[0] == iface:
        return f"udev rule ({hit[1]})", "udev"

    for key, label_ in SYSTEMD_PRIO:
        if block.get(key) == iface:
            if key == "ID_NET_NAME_ONBOARD" and "ID_NET_LABEL_ONBOARD" in block:
                label_ = f"onboard [{block['ID_NET_LABEL_ONBOARD']}]"
            elif key == "ID_NET_NAME_MAC":
                label_ = "mac (non-default policy)"
            return label_, "candidate"

    if iface in rmap["by_name"]:
        return f"udev rule ({rmap['by_name'][iface]})", "udev"
    if iface in ctx.get("link_names", {}):
        return f".link ({ctx['link_names'][iface]})", "link"
    if iface in ctx.get("ifcfg_devices", {}):
        return f"ifcfg DEVICE= ({ctx['ifcfg_devices'][iface]})", "ifcfg"
    if RE_BIOSDEVNAME.match(iface):
        return "biosdevname", "biosdevname"
    if re.match(r"^eth\d+$", iface):
        return "kernel name", "kernel"
    return "unknown (no matching candidate)", "unknown"


def all_candidates(block: dict) -> str:
    """Return all available naming candidates as a comma-separated string."""
    parts = [f"{lbl}={block[k]}" for k, lbl in SYSTEMD_PRIO if k in block]
    return ", ".join(parts) if parts else "—"


def pci_from_block(block: dict) -> str:
    """Return the PCI bus address (e.g. 0000:01:00.0) parsed from ID_PATH, or '—'."""
    m = RE_PCI_PATH.search(block.get("ID_PATH", ""))
    return m.group(1) if m else "—"


def mac_from_block(block: dict) -> str:
    """Return the hardware MAC address (AA:BB:CC:DD:EE:FF) parsed from ID_NET_NAME_MAC, or ''."""
    raw = block.get("ID_NET_NAME_MAC", "")
    if len(raw) >= 14:
        h = raw[-12:].lower()
        if all(c in "0123456789abcdef" for c in h):
            return ":".join(h[i:i + 2] for i in range(0, 12, 2)).upper()
    return ""


def udev_rename_map(udev_rules: list[dict]) -> dict:
    """Build a lookup to explain which custom udev rule renamed a given interface.

    Returns {"by_mac": {mac: (new_name, filename)}, "by_name": {new_name: filename}}.
    Matching is keyed by MAC (ATTR{address}=) because KERNEL== matches the
    pre-rename kernel name, which never equals the post-rename INTERFACE seen
    in the udev DB; by_name is a fallback for rules with no ATTR{address}.
    """
    by_mac: dict[str, tuple[str, str]] = {}
    by_name: dict[str, str] = {}
    for entry in udev_rules:
        for rule in entry["rules"]:
            nm = RE_NAME_VALUE.search(rule)
            if not nm:
                continue
            by_name.setdefault(nm.group(1), entry["file"])
            am = RE_ATTR_ADDR.search(rule)
            if am:
                by_mac[am.group(1).upper()] = (nm.group(1), entry["file"])
    return {"by_mac": by_mac, "by_name": by_name}


def check_mismatch(block: dict, rename_map: dict, source: str = "",
                   kind: str = "") -> tuple[str, bool] | None:
    """Return (message, explained) if ID_NET_NAME disagrees with INTERFACE, else None.

    'explained' is True when a custom udev rule — or the naming source itself
    (biosdevname, prefixdevname, .link, ifcfg DEVICE=) — accounts for the rename
    (worth a note, not a red flag); False when the cause is unknown (warning).
    """
    udev_name = block.get("ID_NET_NAME", "")
    iface = block.get("INTERFACE", block.get("M", ""))
    if not udev_name or udev_name == iface:
        return None

    pci = pci_from_block(block)
    mac = mac_from_block(block)
    by_mac_hit = rename_map["by_mac"].get(mac) if mac else None

    if by_mac_hit and by_mac_hit[0] == iface:
        return (f"MISMATCH: ID_NET_NAME={udev_name} vs INTERFACE={iface}"
                f"  (PCI {pci}, renamed by {by_mac_hit[1]})", True)
    if iface in rename_map["by_name"]:
        return (f"MISMATCH: ID_NET_NAME={udev_name} vs INTERFACE={iface}"
                f"  (PCI {pci}, renamed by {rename_map['by_name'][iface]})", True)
    if kind in ("biosdevname", "link", "ifcfg", "prefixdevname"):
        return (f"MISMATCH: ID_NET_NAME={udev_name} vs INTERFACE={iface}"
                f"  (PCI {pci}, renamed by {source})", True)
    return (f"MISMATCH: ID_NET_NAME={udev_name} vs INTERFACE={iface}  (PCI {pci})", False)


# ---------------------------------------------------------------------------
# Kernel cmdline
# ---------------------------------------------------------------------------

def parse_cmdline(sos_root: Path):
    """Parse proc/cmdline and return relevant naming parameters."""
    f = sos_root / "proc/cmdline"
    if not f.is_file():
        return None
    raw = f.read_text(errors="replace").strip()
    params = {}
    for token in raw.split():
        if "=" in token:
            k, v = token.split("=", 1)
            params[k] = v
        else:
            params[token] = None
    return {
        "raw": raw,
        "net_ifnames": params.get("net.ifnames"),       # "0", "1", or None
        "biosdevname": params.get("biosdevname"),        # "0", "1", or None
        "ifnames_prefix": params.get("net.ifnames.prefix") or None,  # e.g. "net"; empty = unset
        "naming_scheme": params.get("net.naming-scheme"),    # e.g. "rhel-9.4", or None
    }


def rhel_major(sos_root: Path) -> int:
    """RHEL / derivative major release from etc/redhat-release (0 if unknown)."""
    f = sos_root / "etc/redhat-release"
    if not f.is_file():
        return 0
    m = re.search(r"release (\d+)", f.read_text(errors="replace"))
    return int(m.group(1)) if m else 0


def manufacturer(sos_root: Path) -> str:
    """System manufacturer from sos_commands/hardware/dmidecode ('' if unknown)."""
    f = sos_root / "sos_commands/hardware/dmidecode"
    if not f.is_file():
        return ""
    m = re.search(r"^System Information\n(?:\t.*\n)*?\tManufacturer:\s*(.+)$",
                  f.read_text(errors="replace"), re.M)
    return m.group(1).strip() if m else ""


def link_policies(sos_root: Path) -> list[tuple[str, str]]:
    """[(rel_path, NamePolicy)] for every collected .link file setting NamePolicy=."""
    out = []
    for rel_dir in _LINK_DIRS:
        d = sos_root / rel_dir
        if not d.is_dir():
            continue
        for lf in sorted(d.glob("*.link")):
            if not lf.is_file():
                continue
            m = re.search(r"^\s*NamePolicy\s*=\s*(.+?)\s*$",
                          lf.read_text(errors="replace"), re.M)
            if m:
                out.append((f"{rel_dir}/{lf.name}", m.group(1)))
    return out


def is_devnull(p: Path, sos_root: Path) -> bool:
    """True if p is a symlink to /dev/null — sos rewrites absolute links as
    relative to the sosreport root (e.g. ../../../dev/null)."""
    if not p.is_symlink():
        return False
    tgt = os.readlink(p)
    return tgt == "/dev/null" or \
        os.path.normpath(p.parent / tgt) == os.path.normpath(sos_root / "dev" / "null")


def find_masked(sos_root: Path) -> list[dict]:
    """Naming-related udev rules / .link files masked with a link to /dev/null.

    A mask only works if a file with the same name exists in usr/lib/: on
    RHEL 7 80-net-name-slot.rules does, on RHEL 8+ it was dropped (naming goes
    through 80-net-setup-link.rules + 99-default.link), so the classic RHEL 7
    mask left behind by old kickstarts/images has no effect there.
    Returns [{file, lib_dir, state}] with state effective|ineffective|unknown.
    """
    results = []
    for etc_rel, lib_rel, pattern in (
        ("etc/udev/rules.d",    "usr/lib/udev/rules.d",    "*net*.rules"),
        ("etc/udev/rules.d",    "usr/lib/udev/rules.d",    "71-*devname.rules"),
        ("etc/systemd/network", "usr/lib/systemd/network", "*.link"),
    ):
        etc_dir = sos_root / etc_rel
        if not etc_dir.is_dir():
            continue
        lib_dir = sos_root / lib_rel
        for f in sorted(etc_dir.glob(pattern)):
            if not is_devnull(f, sos_root):
                continue
            if not lib_dir.is_dir():
                state = "unknown"
            elif (lib_dir / f.name).is_file():
                state = "effective"
            else:
                state = "ineffective"
            results.append({"file": f.name, "lib_dir": lib_rel, "state": state})
    return results


def print_cmdline_section(cmdline, sos_root: Path, naming_scheme: str | None,
                          blocks: list[dict]) -> None:
    subsection("Kernel cmdline  (net.ifnames / biosdevname / net.ifnames.prefix / net.naming-scheme)")
    major = rhel_major(sos_root)
    # RHEL 7 Networking Guide §11.9 ex. 11.3: kernel ethX names only "work
    # correctly" with a single NIC, or with virtio NICs in RHEL 7 guests.
    drivers = {b.get("ID_NET_DRIVER", "") for b in blocks}
    if major == 7 and len(blocks) == 1:
        ethx_ok = "supported case: single NIC on RHEL 7"
    elif major == 7 and blocks and drivers == {"virtio_net"}:
        ethx_ok = "supported case: all NICs are virtio on RHEL 7"
    else:
        ethx_ok = ""
    print()

    if cmdline is None:
        label("proc/cmdline not found in sosreport")
    else:
        ni = cmdline["net_ifnames"]
        if ni is None:
            kv("net.ifnames", f"{DIM}not set{RESET}  (default: enabled on RHEL 7+)")
        elif ni == "1":
            ok("net.ifnames=1  →  predictable naming enabled")
        elif ni == "0" and ethx_ok:
            note(f"net.ifnames=0  →  predictable naming disabled — {ethx_ok} "
                 f"(RHEL 7 Networking Guide §11.9 ex. 11.3)")
        elif ni == "0":
            warn("net.ifnames=0  →  predictable naming DISABLED",
                 "likely cause of eth* names instead of enXXX",
                 "Red Hat does not support systems with consistent device naming disabled")
        else:
            kv("net.ifnames", f"{ni}  (non-standard value)")

        bd = cmdline["biosdevname"]
        if bd is None:
            kv("biosdevname", f"{DIM}not set{RESET}  (default: disabled on RHEL 8+)")
        elif bd == "0":
            ok("biosdevname=0  →  disabled")
        elif bd == "1":
            warn("biosdevname=1  →  ENABLED", "likely cause of em* / p*p* names")
        else:
            kv("biosdevname", f"{bd}  (non-standard value)")
        if (sos_root / "usr/lib/udev/rules.d/71-biosdevname.rules").is_file():
            mfr = manufacturer(sos_root)
            if "dell" in mfr.lower():
                if bd != "0":
                    note("biosdevname installed on a Dell system — it renames interfaces "
                         "(em*, p*p*) unless biosdevname=0 is on the cmdline")
            else:
                note(f"biosdevname installed on a non-Dell system ({mfr or 'manufacturer unknown'}) "
                     f"— Red Hat: install and use biosdevname only on Dell systems")

        prefix = cmdline.get("ifnames_prefix")
        if prefix is None:
            kv("net.ifnames.prefix", f"{DIM}not set{RESET}")
        else:
            note(f"net.ifnames.prefix={prefix}  →  prefixdevname active: interfaces named "
                 f"{prefix}0, {prefix}1, … (bypasses predictable naming)")
            prefix_rules = sos_root / "usr/lib/udev/rules.d/71-prefixdevname.rules"
            if not prefix_rules.exists():
                warn("71-prefixdevname.rules not found in usr/lib/udev/rules.d/",
                     "prefixdevname package may not be installed")

    nns = cmdline.get("naming_scheme") if cmdline else None
    kv("net.naming-scheme", nns if nns else f"{DIM}not set{RESET}")
    if naming_scheme:
        kv("naming scheme", naming_scheme)
    elif major == 7:
        kv("naming scheme", f"{DIM}n/a on RHEL 7 (net naming schemes start with RHEL 8){RESET}")
    else:
        kv("naming scheme", f"{DIM}not found in udev DB{RESET}")
    if nns and naming_scheme and nns != naming_scheme:
        warn(f"net.naming-scheme={nns} on the cmdline but udev used {naming_scheme}",
             "reboot pending, or the initramfs was not rebuilt (dracut -f)?")

    policies = link_policies(sos_root)
    lib_default = next((pol for f, pol in policies
                        if f == "usr/lib/systemd/network/99-default.link"), None)
    if lib_default:
        kv("NamePolicy", f"{lib_default}  {DIM}(usr/lib/systemd/network/99-default.link){RESET}")
    elif major in DEFAULT_POLICY:
        pol, where = DEFAULT_POLICY[major]
        kv("NamePolicy", f"{pol}  {DIM}({where}){RESET}")
    for f, pol in policies:
        if f.startswith("etc/"):
            extra = " — the mac policy is not used by default" if "mac" in pol.split() else ""
            note(f"{Path(f).name}: NamePolicy={pol} overrides the default for the "
                 f"interfaces it matches{extra}")

    eth_names = sorted(b.get("INTERFACE", "") for b in blocks
                       if re.match(r"^eth\d+$", b.get("INTERFACE", "")))
    for m in find_masked(sos_root):
        if m["file"].startswith("71-"):            # biosdevname / prefixdevname: optional
            tool = m["file"][len("71-"):-len(".rules")]
            if m["state"] == "effective":
                note(f"{m['file']} masked (→ /dev/null) — {tool} renaming disabled")
                pfx = cmdline.get("ifnames_prefix") if cmdline else None
                if tool == "prefixdevname" and pfx:
                    warn(f"net.ifnames.prefix={pfx} is set but 71-prefixdevname.rules is masked "
                         f"— interfaces will not get {pfx}<n> names")
            elif m["state"] == "ineffective":
                note(f"{m['file']} masked (→ /dev/null) but {tool} is not installed — no effect")
            else:
                note(f"{m['file']} masked (→ /dev/null) — {m['lib_dir']}/ not collected, "
                     f"effect not verifiable")
            continue
        if m["state"] == "effective" and eth_names and ethx_ok:
            note(f"Consistent naming disabled: {m['file']} masked (→ /dev/null) — "
                 f"interfaces keep kernel names ({', '.join(eth_names)}); {ethx_ok} "
                 f"(RHEL 7 Networking Guide §11.9 ex. 11.3)")
        elif m["state"] == "effective":
            warn(f"Consistent naming disabled: {m['file']} masked (→ /dev/null) — "
                 f"interfaces keep kernel names (eth*)",
                 f"kernel names in use: {', '.join(eth_names)}" if eth_names else
                 "but interfaces still have predictable names — mask added after the "
                 "last boot, or initramfs not rebuilt (dracut -f)?",
                 "Red Hat does not support systems with consistent device naming disabled")
        elif m["state"] == "ineffective":
            note(f"{m['file']} masked (→ /dev/null) but no such file in {m['lib_dir']}/ "
                 f"on this release — mask has no effect (RHEL 8+ names via "
                 f"80-net-setup-link.rules + 99-default.link; leftover from a RHEL 7 image/kickstart?)")
        else:
            note(f"{m['file']} masked (→ /dev/null) — {m['lib_dir']}/ not collected, "
                 f"effect not verifiable")


# ---------------------------------------------------------------------------
# Custom udev rules
# ---------------------------------------------------------------------------

def find_udev_custom_rules(sos_root: Path) -> list[dict]:
    """Find rules in etc/udev/rules.d/ that rename network interfaces."""
    rules_dir = sos_root / "etc/udev/rules.d"
    if not rules_dir.is_dir():
        return []
    results = []
    for rf in sorted(rules_dir.glob("*.rules")):
        if not rf.is_file():          # mask → /dev/null or dangling link
            continue
        found = []
        for line in rf.read_text(errors="replace").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            if RE_NAME_ASSIGN.search(s) and RE_NET_INDICATOR.search(s):
                found.append(s)
        if found:
            results.append({"file": rf.name, "rules": found})
    return results


def print_udev_rules_section(rules: list[dict]) -> None:
    subsection("Custom udev rules  (etc/udev/rules.d/)")
    print()
    if not rules:
        ok("No network renaming rules in etc/udev/rules.d/")
    else:
        note(f"{len(rules)} file(s) with network NAME= rules found")
        for entry in rules:
            print(f"    {BOLD}{entry['file']}{RESET}")
            for rule in entry["rules"]:
                print(f"      {DIM}{rule}{RESET}")
        # RHEL 8/9/10 "Configuring user-defined network interface names by using
        # udev rules": dracut only copies 70-persistent-net.rules into the initrd
        for entry in rules:
            if entry["file"] != "70-persistent-net.rules":
                note(f"{entry['file']}: renaming rules outside 70-persistent-net.rules are not "
                     f"copied into the initrd by dracut — names can differ during early boot "
                     f"(network root / iSCSI)")


# ---------------------------------------------------------------------------
# systemd .link files
# ---------------------------------------------------------------------------

def find_link_files(sos_root: Path) -> list[dict]:
    """Find .link files that set Name= in their [Link] section."""
    results = []
    for rel_dir in _LINK_DIRS:
        d = sos_root / rel_dir
        if not d.is_dir():
            continue
        for lf in sorted(d.glob("*.link")):
            if not lf.is_file():      # mask → /dev/null or dangling link
                continue
            cfg = configparser.ConfigParser(strict=False)
            cfg.optionxform = str  # preserve key case (Name, MACAddress, …)
            try:
                cfg.read_string(lf.read_text(errors="replace"))
            except configparser.Error:
                continue
            if cfg.has_section("Link") and cfg.has_option("Link", "Name"):
                match_items = dict(cfg.items("Match")) if cfg.has_section("Match") else {}
                results.append({
                    "file": str(lf.relative_to(sos_root)),
                    "match": match_items,
                    "name": cfg.get("Link", "Name"),
                })
    return results


def print_link_files_section(links: list[dict]) -> None:
    subsection("systemd .link files  (etc/systemd/network  /  usr/lib/systemd/network)")
    print()
    if not links:
        ok("No .link files with Name= override found")
    else:
        note(f"{len(links)} .link file(s) with Name= override")
        for lf in links:
            print(f"    {BOLD}{lf['file']}{RESET}  →  {CYAN}Name={lf['name']}{RESET}")
            for k, v in lf["match"].items():
                print(f"      {DIM}Match: {k}={v}{RESET}")


# ---------------------------------------------------------------------------
# ifcfg HWADDR renaming (legacy rename_device / 60-net.rules)
# ---------------------------------------------------------------------------

def find_ifcfg_hwaddr(sos_root: Path) -> list[dict]:
    """Find ifcfg-* scripts with HWADDR=.

    'device' is '' when DEVICE= is absent from the same file: the interface
    is only bound to that MAC by NetworkManager, rename_device is not
    triggered.
    """
    scripts_dir = sos_root / "etc/sysconfig/network-scripts"
    if not scripts_dir.is_dir():
        return []
    results = []
    for ifcfg in sorted(scripts_dir.glob("ifcfg-*")):
        if not ifcfg.is_file():       # mask → /dev/null or dangling link
            continue
        hwaddr = device = None
        for line in ifcfg.read_text(errors="replace").splitlines():
            s = line.strip()
            if s.upper().startswith("HWADDR="):
                hwaddr = s.split("=", 1)[1].strip().strip('"').upper()
            elif s.upper().startswith("DEVICE="):
                device = s.split("=", 1)[1].strip().strip('"')
        if hwaddr:
            results.append({"file": ifcfg.name, "hwaddr": hwaddr, "device": device or ""})
    return results


def has_60_net_rules(sos_root: Path) -> bool:
    return ((sos_root / "usr/lib/udev/rules.d/60-net.rules").exists()
            or (sos_root / "etc/udev/rules.d/60-net.rules").exists())


def print_ifcfg_section(sos_root: Path, blocks: list[dict], entries: list[dict],
                        net_rules: bool) -> None:
    subsection("ifcfg HWADDR renaming  (60-net.rules / rename_device)")

    rules_usr = sos_root / "usr/lib/udev/rules.d"
    print()
    # 60-net.rules (initscripts / initscripts-rename-device) runs rename_device
    # only for ifcfg-* with HWADDR= — "udev skips this step" otherwise.
    if net_rules and entries:
        kv("60-net.rules", f"{GREEN}present{RESET}  (rename_device active)")
    elif net_rules:
        kv("60-net.rules", f"present  {DIM}(inactive: no ifcfg-* file with HWADDR=){RESET}")
    elif rules_usr.is_dir():
        kv("60-net.rules", f"{DIM}not found  (initscripts-rename-device not installed){RESET}")
    else:
        kv("60-net.rules", f"{DIM}not verifiable  (usr/lib/udev/rules.d/ not collected){RESET}")

    if not entries:
        ok("No ifcfg-* files with HWADDR= found")
        return

    mac_to_iface: dict[str, str] = {}
    for b in blocks:
        mac = mac_from_block(b)
        if mac:
            mac_to_iface[mac] = b.get("INTERFACE", b.get("M", "?"))

    with_device    = [e for e in entries if e["device"]]
    without_device = [e for e in entries if not e["device"]]
    parts = []
    if with_device:
        parts.append(f"{len(with_device)} rename_device candidate(s)")
    if without_device:
        parts.append(f"{len(without_device)} NM binding-only")
    note(f"{len(entries)} ifcfg file(s) with HWADDR=  ({', '.join(parts)})")

    headers = ("ifcfg file", "HWADDR", "DEVICE", "Matched interface")
    rows = []
    for e in entries:
        matched   = mac_to_iface.get(e["hwaddr"], "")
        dev_col   = e["device"] if e["device"] else "—"
        match_col = f"-> {matched}" if matched else "(not in udev DB)"
        rows.append((e["file"], e["hwaddr"], dev_col, match_col))

    col_widths = [
        max(len(headers[i]), *(len(r[i]) for r in rows)) + 2
        for i in range(len(headers))
    ]
    print()
    tbl_header(*zip(headers, col_widths))
    for row in rows:
        print("    " + "  ".join(
            f"{row[i]:<{col_widths[i]}}" for i in range(len(row))
        ))

    for e in entries:
        matched = mac_to_iface.get(e["hwaddr"], "")
        if e["device"]:
            if not net_rules and rules_usr.is_dir():
                warn(f"{e['file']}: DEVICE={e['device']} with HWADDR= but 60-net.rules is not "
                     f"installed — rename_device never runs, the interface keeps its udev name"
                     + (f" ({matched})" if matched else ""),
                     "install initscripts-rename-device, or rename with a .link file / "
                     "70-persistent-net.rules")
            elif not matched:
                warn(f"HWADDR {e['hwaddr']} in {e['file']} not matched to any known interface")
            elif matched == e["device"]:
                note(f"{matched} ({e['hwaddr']})  →  already named {e['device']} "
                     f"(rename_device via {e['file']} is a no-op)")
            elif re.match(r"^eth\d+$", e["device"]):
                warn(f"{e['file']}: renames {matched} to {e['device']} in the kernel namespace — "
                     f"fails ('File exists') when the kernel already uses that name",
                     "RHEL 7 Networking Guide §11.9 ex. 11.3: use a non-ethX name")
            else:
                note(f"{matched} ({e['hwaddr']})  →  rename_device renames to "
                     f"'{e['device']}' via {e['file']}  (not applied yet in this sosreport)")
        else:
            if matched:
                note(f"{matched} ({e['hwaddr']})  →  NM binding via {e['file']} "
                     f"(no DEVICE=, rename_device not triggered)")
            else:
                warn(f"HWADDR {e['hwaddr']} in {e['file']} not matched to any known interface")


# ---------------------------------------------------------------------------
# CLI argument resolution
# ---------------------------------------------------------------------------

def escaping_links(sos_root: Path) -> list[tuple[str, str]]:
    """[(relative path, link target)] for symlinks resolving outside the sosreport.
    sos only writes links inside the report (masks point to its own dev/null), so
    an escaping link means a crafted archive that would make ifname read and print
    files of the analyst's machine."""
    root = os.path.realpath(sos_root)
    out = []
    for dp, dns, fns in os.walk(sos_root):          # does not follow directory links
        for n in dns + fns:
            p = os.path.join(dp, n)
            if not os.path.islink(p):
                continue
            tgt, rp = os.readlink(p), os.path.realpath(p)
            if tgt == "/dev/null" or rp == root or rp.startswith(root + os.sep):
                continue
            out.append((os.path.relpath(p, sos_root), tgt))
    return out


def resolve_sos_root(arg: str) -> Path:
    """Resolve the sosreport root from a CLI argument that may be the root
    directory itself, or a direct path to the udev DB file."""
    p = Path(arg)
    if p.is_file():
        db_parts = UDEVADM_DB.parts
        if p.parts[-len(db_parts):] == db_parts:
            root_parts = p.parts[:-len(db_parts)]
            return Path(*root_parts) if root_parts else Path(".")
        return p.parent
    return p


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Diagnose network interface renaming from a systemd udev database (e.g. a sosreport)."
    )
    ap.add_argument(
        "-v", "--version", action="version",
        version=f"ifname version {__version__} ({__build_date__}) by manumaiden",
    )
    ap.add_argument("sosreport", nargs="?", default=".",
                    help="Path to the sosreport root directory, or directly to its "
                         "udevadm_info_--export-db file (default: current directory)")
    ap.add_argument("-d", "--detail", action="store_true",
                    help="Show all naming candidates and flag mismatches")
    ap.add_argument("--no-color", action="store_true",
                    help="Disable ANSI color output (auto-disabled when stdout is not a TTY)")
    args = ap.parse_args()

    sos_root = resolve_sos_root(args.sosreport)
    db_path = sos_root / UDEVADM_DB

    red, reset = (RED, RESET) if sys.stderr.isatty() and not args.no_color else ("", "")
    if not db_path.is_file():
        print(f"{red}ERROR: {db_path} not found{reset}\n"
              f"Run from the sosreport root directory, or pass its path as an argument.\n"
              f"A plain 'udevadm info --export-db' dump must be saved as "
              f"<dir>/{UDEVADM_DB}, then run: ifname <dir>",
              file=sys.stderr)
        sys.exit(1)

    outside = escaping_links(sos_root)
    if outside:
        print(f"{red}ERROR: {len(outside)} symlink(s) point outside the sosreport — refusing to "
              f"read files of this machine:{reset}", file=sys.stderr)
        for rel, tgt in outside[:20]:
            print(f"  {_CTRL_RE.sub('', rel)} -> {_CTRL_RE.sub('', tgt)}", file=sys.stderr)
        sys.exit(1)

    sys.stdout = _SafeStream(sys.stdout, color=not (args.no_color or not sys.stdout.isatty()))

    print(f"{DIM}ver. {__version__} ({__build_date__}){RESET}")

    section("INTERFACE NAMING")

    blocks = list(parse_blocks(db_path))
    udev_rules = find_udev_custom_rules(sos_root)
    rename_map = udev_rename_map(udev_rules)
    link_files = find_link_files(sos_root)
    ifcfg_entries = find_ifcfg_hwaddr(sos_root)
    net_rules = has_60_net_rules(sos_root)

    # 1. Cmdline
    cmdline = parse_cmdline(sos_root)
    print_cmdline_section(cmdline, sos_root, get_naming_scheme(blocks), blocks)
    ifnames_prefix = cmdline.get("ifnames_prefix") if cmdline else None

    # 2. Interface table

    subsection("Network interfaces  (udevadm --export-db)")
    if not blocks:
        label("No PCI network interfaces found in udev database")
    else:
        rows = []
        mismatches = []
        src_ctx = {
            "rename_map":    rename_map,
            "link_names":    {lf["name"]: Path(lf["file"]).name for lf in link_files},
            "ifcfg_devices": {e["device"]: e["file"] for e in ifcfg_entries
                              if e["device"]} if net_rules else {},
        }

        for b in blocks:
            iface      = b.get("INTERFACE", b.get("M", "?"))
            pci        = pci_from_block(b)
            source, kind = naming_source(b, ifnames_prefix, src_ctx)
            driver     = b.get("ID_NET_DRIVER", "—")
            scheme     = b.get("ID_NET_NAMING_SCHEME", "—")
            model      = b.get(
                "ID_MODEL_FROM_DATABASE",
                b.get("ID_MODEL_ENC", b.get("ID_MODEL", "—"))
            )
            m = check_mismatch(b, rename_map, source, kind)
            if m:
                mismatches.append(m)

            if args.detail:
                lf = b.get("ID_NET_LINK_FILE", "—")
                rows.append((iface, pci, source, driver, scheme, all_candidates(b), lf, model))
            else:
                rows.append((iface, pci, source, driver, scheme, model))

        rows.sort(key=lambda r: r[0])
        print()

        if args.detail:
            headers = ("Interface", "PCI", "Source", "Driver", "Scheme", "Candidates", "Link file", "Model")
        else:
            headers = ("Interface", "PCI", "Source", "Driver", "Scheme", "Model")

        col_widths = [
            max(len(headers[i]), *(len(str(r[i])) for r in rows)) + 2
            for i in range(len(headers))
        ]
        tbl_header(*zip(headers, col_widths))
        for row in rows:
            print("    " + "  ".join(
                f"{str(row[i]):<{col_widths[i]}}" for i in range(len(row))
            ))

        for msg, explained in mismatches:
            (note if explained else warn)(msg)

    # 3. Custom udev rules
    print_udev_rules_section(udev_rules)

    # 4. systemd .link files
    print_link_files_section(link_files)

    # 5. ifcfg HWADDR renaming
    print_ifcfg_section(sos_root, blocks, ifcfg_entries, net_rules)


if __name__ == "__main__":
    main()
