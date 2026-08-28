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

import argparse
import configparser
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

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


class _NoColorStream:
    """Stdout wrapper that strips ANSI escape codes on every write."""
    def __init__(self, stream):
        self._s = stream

    def write(self, text: str) -> int:
        return self._s.write(_ANSI_RE.sub("", text))

    def flush(self) -> None:
        self._s.flush()

    def isatty(self) -> bool:
        return False

    def fileno(self) -> int:
        return self._s.fileno()


__version__    = "1.0"
__build_date__ = "28082026"

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
        if RE_PCI_NET.match(block.get("P", "")):
            yield block


def get_naming_scheme(db_path: Path) -> str | None:
    """Return the first ID_NET_NAMING_SCHEME value found in the udev DB, or None."""
    for block in parse_blocks(db_path):
        if "ID_NET_NAMING_SCHEME" in block:
            return block["ID_NET_NAMING_SCHEME"]
    return None


def naming_source(block: dict, prefix: str | None = None) -> tuple[str, str]:
    """Return (source_label, chosen_name) explaining how the interface was named."""
    iface = block.get("INTERFACE", block.get("M", "?"))
    has_systemd = any(k in block for k, _ in SYSTEMD_PRIO)

    if prefix and re.match(rf"^{re.escape(prefix)}\d+$", iface):
        return f"prefixdevname [{prefix}<n>]", iface

    if RE_BIOSDEVNAME.match(iface) and not has_systemd:
        return "biosdevname", iface

    for key, label_ in SYSTEMD_PRIO:
        if key in block:
            if key == "ID_NET_NAME_ONBOARD" and "ID_NET_LABEL_ONBOARD" in block:
                label_ = f"onboard [{block['ID_NET_LABEL_ONBOARD']}]"
            return label_, block[key]

    return "none (kernel name)", iface


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


def check_mismatch(block: dict, rename_map: dict) -> tuple[str, bool] | None:
    """Return (message, explained) if ID_NET_NAME disagrees with INTERFACE, else None.

    'explained' is True when a custom udev rule accounts for the rename (worth a
    note, not a red flag); False when the rename cause is unknown (worth a warning).
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
    return (f"MISMATCH: ID_NET_NAME={udev_name} vs INTERFACE={iface}  (PCI {pci})", False)


# ---------------------------------------------------------------------------
# Kernel cmdline
# ---------------------------------------------------------------------------

def parse_cmdline(sos_root: Path):
    """Parse proc/cmdline and return relevant naming parameters."""
    f = sos_root / "proc/cmdline"
    if not f.exists():
        return None
    raw = f.read_text().strip()
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
        "ifnames_prefix": params.get("net.ifnames.prefix"),  # e.g. "net", or None
    }


def print_cmdline_section(cmdline, sos_root: Path, naming_scheme: str | None = None) -> None:
    subsection("Kernel cmdline  (net.ifnames / biosdevname / net.ifnames.prefix)")
    print()

    if cmdline is None:
        label("proc/cmdline not found in sosreport")
        return

    ni = cmdline["net_ifnames"]
    if ni is None:
        kv("net.ifnames", f"{DIM}not set{RESET}  (default: enabled on RHEL 7+)")
    elif ni == "1":
        ok("net.ifnames=1  →  predictable naming enabled")
    elif ni == "0":
        warn("net.ifnames=0  →  predictable naming DISABLED",
             "likely cause of eth* names instead of enXXX")
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

    kv("naming scheme", naming_scheme if naming_scheme else f"{DIM}not found in udev DB{RESET}")


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


# ---------------------------------------------------------------------------
# systemd .link files
# ---------------------------------------------------------------------------

_LINK_DIRS = ("etc/systemd/network", "usr/lib/systemd/network")


def find_link_files(sos_root: Path) -> list[dict]:
    """Find .link files that set Name= in their [Link] section."""
    results = []
    for rel_dir in _LINK_DIRS:
        d = sos_root / rel_dir
        if not d.is_dir():
            continue
        for lf in sorted(d.glob("*.link")):
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


def print_ifcfg_section(sos_root: Path, blocks: list[dict]) -> None:
    subsection("ifcfg HWADDR renaming  (60-net.rules / rename_device)")

    net_rules = ((sos_root / "usr/lib/udev/rules.d/60-net.rules").exists()
                 or (sos_root / "etc/udev/rules.d/60-net.rules").exists())
    print()
    if net_rules:
        kv("60-net.rules", f"{GREEN}present{RESET}  (rename_device active)")
    else:
        kv("60-net.rules", f"{DIM}not found in udev/rules.d/{RESET}")

    entries = find_ifcfg_hwaddr(sos_root)
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
            if matched:
                note(f"{matched} ({e['hwaddr']})  →  rename_device renames to "
                     f"'{e['device']}' via {e['file']}")
            else:
                warn(f"HWADDR {e['hwaddr']} in {e['file']} not matched to any known interface")
        else:
            if matched:
                note(f"{matched} ({e['hwaddr']})  →  NM binding via {e['file']} "
                     f"(no DEVICE=, rename_device not triggered)")
            else:
                warn(f"HWADDR {e['hwaddr']} in {e['file']} not matched to any known interface")


# ---------------------------------------------------------------------------
# CLI argument resolution
# ---------------------------------------------------------------------------

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

    if not db_path.exists():
        print(f"{RED}ERROR: {db_path} not found{RESET}\n"
              f"Run from the sosreport root directory, or pass its path as an argument.",
              file=sys.stderr)
        sys.exit(1)

    if args.no_color or not sys.stdout.isatty():
        sys.stdout = _NoColorStream(sys.stdout)

    print(f"{DIM}ver. {__version__} ({__build_date__}){RESET}")

    section("INTERFACE NAMING")

    # 1. Cmdline
    cmdline = parse_cmdline(sos_root)
    print_cmdline_section(cmdline, sos_root, get_naming_scheme(db_path))
    ifnames_prefix = cmdline.get("ifnames_prefix") if cmdline else None

    # 2. Interface table
    blocks = list(parse_blocks(db_path))
    udev_rules = find_udev_custom_rules(sos_root)
    rename_map = udev_rename_map(udev_rules)

    subsection("Network interfaces  (udevadm --export-db)")
    if not blocks:
        label("No PCI network interfaces found in udev database")
    else:
        rows = []
        mismatches = []

        for b in blocks:
            iface      = b.get("INTERFACE", b.get("M", "?"))
            pci        = pci_from_block(b)
            source, _  = naming_source(b, ifnames_prefix)
            driver     = b.get("ID_NET_DRIVER", "—")
            scheme     = b.get("ID_NET_NAMING_SCHEME", "—")
            model      = b.get(
                "ID_MODEL_FROM_DATABASE",
                b.get("ID_MODEL_ENC", b.get("ID_MODEL", "—"))
            )
            m = check_mismatch(b, rename_map)
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
    print_link_files_section(find_link_files(sos_root))

    # 5. ifcfg HWADDR renaming
    print_ifcfg_section(sos_root, blocks)


if __name__ == "__main__":
    main()
