#!/usr/bin/env python3
"""
zuzu-system-info.py

Python port of the original system snapshot + report tooling.

Collects a structured system snapshot (plain text files) and optionally
generates a Markdown report suitable for humans and LLMs.

Features:
  - Generic Linux info + distro-specific package handling
  - Supports: Debian/Ubuntu/Raspbian, Arch, RHEL/Fedora/CentOS/Rocky/Alma, SUSE
  - Package section modes: suppress | minimal | verbose
  - Optional anonymization of sensitive data in the Markdown report
  - LLM‑friendly Markdown:
      * tables for summaries
      * raw blocks only where they add value (e.g. os-release, nft ruleset)
  - Network listening sockets snapshot (ss -lntu) included in snapshot
    and summarized in the report.

Usage:
  zuzu-system-info.py [options]

Options:
  -o, --output-dir DIR     Directory to write snapshot & report (default: ./reports)
      --no-report          Do not generate Markdown report, only raw snapshot files
      --packages MODE      Package mode: suppress|minimal|verbose (default: minimal)
      --anonymize          Anonymize sensitive data in the Markdown report
      --sections LIST      Comma-separated: meta,os,hardware,network,firewall,
                           services,docker,packages,all (default: all)
      --split-reports      One Markdown file per section instead of a single report
  -h, --help               Show this help
"""

import argparse
import datetime
import os
import platform
import re
import shutil
import subprocess
import json

from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any, Set

SCRIPT_DIR = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def run_cmd(cmd: List[str]) -> str:
    """
    Run a command and return stdout+stderr as a string.
    If the command is missing or fails, return an informative message.
    """
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=False,
        )
        return result.stdout.strip()
    except FileNotFoundError:
        return f"(command not available: {' '.join(cmd)})"
    except Exception as e:
        return f"(command failed: {' '.join(cmd)}: {e})"


def safe_cmd(args: List[str]) -> str:
    """
    Run a command and normalize the 'command not available' noise.
    Many build_* functions use this instead of run_cmd directly so they
    can silently skip missing tools.
    """
    try:
        out = run_cmd(args)
    except Exception:
        return ""
    out = (out or "").strip()
    if "command not available" in out.lower():
        return ""
    return out


def md_table(headers: List[str], rows: List[List[str]]) -> List[str]:
    """
    Build a Markdown table as a list of lines.

    All section builders use this helper so table formatting is consistent
    and LLM-friendly.
    """
    lines: List[str] = []
    # header
    lines.append("| " + " | ".join(headers) + " |")
    # separator row – simple, LLM-friendly
    lines.append("|" + "|".join(["---"] * len(headers)) + "|")
    # rows
    for row in rows:
        safe = [("" if c is None else str(c)).replace("\n", " ").strip() for c in row]
        lines.append("| " + " | ".join(safe) + " |")
    lines.append("")  # blank line after table
    return lines


# ---------------------------------------------------------------------------
# Distro detection
# ---------------------------------------------------------------------------

def detect_distro() -> Tuple[str, str]:
    """
    Parse /etc/os-release and return (ID, ID_LIKE).
    If not found, returns ("unknown", "").
    """
    os_release = Path("/etc/os-release")
    if not os_release.is_file():
        return "unknown", ""

    data: Dict[str, str] = {}
    for line in os_release.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            data[k] = v.strip().strip('"')

    distro_id = data.get("ID", "unknown")
    distro_like = data.get("ID_LIKE", "")
    return distro_id, distro_like


def detect_family(distro_id: str, distro_like: str) -> str:
    """
    Map distro id / like into a coarse family:
      debian, arch, rhel, suse, unknown
    """
    def norm(s: str) -> str:
        return s.lower()

    idn = norm(distro_id)
    liken = norm(distro_like)

    if any(x in idn for x in ("debian", "ubuntu", "raspbian")) or any(
            x in liken for x in ("debian", "ubuntu")
    ):
        return "debian"
    if "arch" in idn or "arch" in liken:
        return "arch"
    if any(x in idn for x in ("rhel", "fedora", "centos", "rocky", "almalinux")) or any(
            x in liken for x in ("rhel", "fedora", "centos")
    ):
        return "rhel"
    if any(x in idn for x in ("sles", "opensuse", "suse")) or any(
            x in liken for x in ("sles", "suse", "opensuse")
    ):
        return "suse"
    return "unknown"


# ---------------------------------------------------------------------------
# Snapshot collectors: write raw text files to the snapshot dir
# ---------------------------------------------------------------------------

def write_section_with_commands(path: Path, sections: List[Tuple[str, List[str]]]) -> None:
    """
    Utility (not used heavily in this script right now, but kept around):

    Write a file where each section is:
      == <label> ==
      <command output>

    sections: list of (label, commandlist)
    """
    lines: List[str] = []
    for label, cmd in sections:
        cmd_str = " ".join(cmd)
        header = f"== {label or cmd_str} =="
        lines.append(header)
        lines.append(run_cmd(cmd))
        lines.append("")  # blank line
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def collect_meta(
        meta_file: Path,
        snapshot_dir: Path,
        hostname: str,
        timestamp: str,
        distro_id: str,
        distro_like: str,
) -> None:
    lines: List[str] = []
    lines.append("== Snapshot metadata ==")
    lines.append(f"Host: {hostname}")
    lines.append(f"Timestamp: {timestamp}")
    lines.append(f"Snapshot dir: {snapshot_dir}")
    lines.append(f"Distro ID: {distro_id}")
    lines.append(f"Distro like: {distro_like}")
    lines.append("")
    lines.append("== date ==")
    lines.append(run_cmd(["date"]))
    lines.append("")
    lines.append("== uptime ==")
    lines.append(run_cmd(["uptime"]))
    lines.append("")
    lines.append("== who ==")
    lines.append(run_cmd(["who"]))
    lines.append("")
    meta_file.write_text("\n".join(lines), encoding="utf-8")


def collect_os(os_file: Path) -> None:
    lines: List[str] = []
    lines.append("== uname -a ==")
    lines.append(run_cmd(["uname", "-a"]))
    lines.append("")
    lines.append("== uname -r ==")
    lines.append(run_cmd(["uname", "-r"]))
    lines.append("")
    lines.append("== uname -m ==")
    lines.append(run_cmd(["uname", "-m"]))
    lines.append("")
    lines.append("== hostnamectl ==")
    lines.append(run_cmd(["hostnamectl"]))
    lines.append("")
    lines.append("== /etc/os-release ==")
    if Path("/etc/os-release").is_file():
        contents = Path("/etc/os-release").read_text(encoding="utf-8", errors="ignore")
        lines.extend("  " + l for l in contents.splitlines())
    else:
        lines.append("(no /etc/os-release)")
    lines.append("")
    lines.append("== lsb_release -a ==")
    lines.append(run_cmd(["lsb_release", "-a"]))
    lines.append("")
    lines.append("== ldd --version (first line) ==")
    out = run_cmd(["ldd", "--version"])
    first_line = out.splitlines()[0] if out else "(no output)"
    lines.append(first_line)
    lines.append("")
    os_file.write_text("\n".join(lines), encoding="utf-8")


def collect_os_distro_specific(os_file: Path, family: str, distro_id: str) -> None:
    lines: List[str] = []
    lines.append("== Distro-specific OS details ==")

    if family == "debian":
        lines.append("== /etc/debian_version ==")
        if Path("/etc/debian_version").is_file():
            lines.append(Path("//etc/debian_version").read_text().strip())
        else:
            lines.append("(no /etc/debian_version)")
        lines.append("")
        if shutil.which("dpkg"):
            lines.append("== dpkg --print-architecture ==")
            lines.append(run_cmd(["dpkg", "--print-architecture"]))
            lines.append("")
            lines.append("== dpkg --print-foreign-architectures ==")
            lines.append(run_cmd(["dpkg", "--print-foreign-architectures"]))
            lines.append("")
    elif family == "arch":
        arch_rel = Path("/etc/arch-release")
        if arch_rel.is_file():
            lines.append("== /etc/arch-release ==")
            content = arch_rel.read_text(encoding="utf-8", errors="ignore").strip()
            if content:
                lines.append(content)
            else:
                lines.append("(present but empty marker file)")
            lines.append("")
    elif family == "rhel":
        if Path("/etc/redhat-release").is_file():
            lines.append("== /etc/redhat-release ==")
            lines.append(Path("/etc/redhat-release").read_text().strip())
            lines.append("")
    elif family == "suse":
        if Path("/etc/SuSE-release").is_file():
            lines.append("== /etc/SuSE-release ==")
            lines.append(Path("/etc/SuSE-release").read_text().strip())
            lines.append("")

    # Append if we added anything real
    text = "\n".join(lines).strip()
    if text and text != "== Distro-specific OS details ==":
        with os_file.open("a", encoding="utf-8") as f:
            f.write("\n" + text + "\n")


def collect_hw(hw_file: Path) -> None:
    lines: List[str] = []
    lines.append("== lscpu ==")
    lines.append(run_cmd(["lscpu"]))
    lines.append("")
    lines.append("== free -h ==")
    lines.append(run_cmd(["free", "-h"]))
    lines.append("")
    lines.append("== lsblk ==")
    lines.append(run_cmd(["lsblk", "-o", "NAME,FSTYPE,SIZE,MOUNTPOINT,TYPE,MODEL"]))
    lines.append("")
    lines.append("== df -h ==")
    lines.append(run_cmd(["df", "-h"]))
    lines.append("")
    hw_file.write_text("\n".join(lines), encoding="utf-8")


def collect_net(net_file: Path) -> None:
    """
    Collect network basics + listening sockets in a single host_net-style file.
    """
    lines: List[str] = []
    lines.append("== ip -br addr ==")
    lines.append(run_cmd(["ip", "-br", "addr"]))
    lines.append("")
    lines.append("== ip route ==")
    lines.append(run_cmd(["ip", "route"]))
    lines.append("")
    lines.append("== ip -6 route ==")
    lines.append(run_cmd(["ip", "-6", "route"]))
    lines.append("")
    lines.append("== resolv.conf ==")
    if Path("/etc/resolv.conf").is_file():
        contents = Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="ignore")
        lines.extend("  " + l for l in contents.splitlines())
    else:
        lines.append("(no /etc/resolv.conf)")
    lines.append("")
    lines.append("== ss -lntu ==")
    lines.append(run_cmd(["ss", "-lntu"]))
    lines.append("")
    net_file.write_text("\n".join(lines), encoding="utf-8")


def collect_fw(fw_file: Path) -> None:
    lines: List[str] = []
    lines.append("== iptables -L -n -v ==")
    lines.append(run_cmd(["iptables", "-L", "-n", "-v"]))
    lines.append("")
    lines.append("== ip6tables -L -n -v ==")
    lines.append(run_cmd(["ip6tables", "-L", "-n", "-v"]))
    lines.append("")
    lines.append("== nft list ruleset ==")
    lines.append(run_cmd(["nft", "list", "ruleset"]))
    lines.append("")
    lines.append("== ufw status verbose ==")
    lines.append(run_cmd(["ufw", "status", "verbose"]))
    lines.append("")
    fw_file.write_text("\n".join(lines), encoding="utf-8")


def collect_services(srv_file: Path) -> None:
    lines: List[str] = []
    lines.append("== systemctl list-units --type=service ==")
    lines.append(run_cmd(["systemctl", "list-units", "--type=service", "--no-pager"]))
    lines.append("")
    lines.append("== systemctl --failed ==")
    lines.append(run_cmd(["systemctl", "--failed", "--no-pager"]))
    lines.append("")
    srv_file.write_text("\n".join(lines), encoding="utf-8")


def collect_docker(docker_file: Path) -> None:
    """
    Raw Docker snapshot: engine info + container / network / volume / images lists.

    The report-building code uses structured JSON via docker --format, but this
    raw dump is kept for deep debugging or non-LLM analysis.
    """
    lines: List[str] = []

    lines.append("== docker info ==")
    lines.append(run_cmd(["docker", "info"]))
    lines.append("")

    lines.append("== docker ps ==")
    lines.append(
        run_cmd(
            [
                "docker",
                "ps",
                "--format",
                "table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}\t{{.Names}}",
            ]
        )
    )
    lines.append("")

    # Build a set of interface names from ip -br addr so we can validate bridge names
    ip_br = run_cmd(["ip", "-br", "addr"])
    iface_names = set()
    for ln in ip_br.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        iface = ln.split()[0]
        iface_names.add(iface)

    # Enhanced docker network listing with inferred bridge iface
    lines.append("== docker network ls (with bridge iface) ==")
    if shutil.which("docker") is None:
        lines.append("(docker not available)")
    else:
        raw = run_cmd(
            [
                "docker",
                "network",
                "ls",
                "--format",
                "{{.ID}}\t{{.Name}}\t{{.Driver}}\t{{.Scope}}",
            ]
        )

        fmt = "{:<12}  {:<24}  {:<8}  {:<7}  {}"
        lines.append(fmt.format("NETWORK ID", "NAME", "DRIVER", "SCOPE", "BRIDGE_IFACE"))

        for ln in raw.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            parts = ln.split("\t")
            if len(parts) < 4:
                lines.append(ln)
                continue

            net_id, name, driver, scope = parts[:4]
            bridge_iface = "-"

            if driver == "bridge":
                candidates = []

                if name == "bridge":
                    candidates.append("docker0")

                candidates.append(f"br-{net_id[:12]}")
                candidates.append(name)

                for cand in candidates:
                    if cand in iface_names:
                        bridge_iface = cand
                        break

            lines.append(fmt.format(net_id, name, driver, scope, bridge_iface))

    lines.append("")

    lines.append("== docker volume ls ==")
    lines.append(run_cmd(["docker", "volume", "ls"]))
    lines.append("")

    lines.append("== docker images ==")
    lines.append(
        run_cmd(
            [
                "docker",
                "images",
                "--format",
                "table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}\t{{.CreatedSince}}\t{{.Containers}}",
            ]
        )
    )
    lines.append("")

    docker_file.write_text("\n".join(lines), encoding="utf-8")


# ---------------------------------------------------------------------------
# Package collection (raw snapshot)
# ---------------------------------------------------------------------------

def load_core_patterns(family: str) -> Optional[List[re.Pattern]]:
    """
    Try to load regex patterns for 'core' packages from:
      core-packages-<family>.patterns
    falling back to:
      core-packages-generic.patterns

    Returns list of compiled regex patterns, or None if none found.
    """
    candidates = [
        SCRIPT_DIR / f"core-packages-{family}.patterns",
        SCRIPT_DIR / "core-packages-generic.patterns",
        ]
    path: Optional[Path] = None
    for p in candidates:
        if p.is_file():
            path = p
            break

    if path is None:
        return None

    patterns: List[re.Pattern] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            patterns.append(re.compile(line))
        except re.error:
            # Skip bad regexes instead of crashing the script
            continue
    return patterns or None


def collect_packages(pkg_file: Path, family: str, pkg_mode: str, tmp_dir: Path) -> None:
    """
    Package collection logic:
      - suppress: record that packages were suppressed.
      - minimal: only 'core' packages based on external patterns.
      - verbose: full package list from dpkg/pacman/rpm.

    The snapshot format is intentionally simple and shared across families
    so the Markdown builder can parse it generically.
    """
    if pkg_mode == "suppress":
        pkg_file.write_text(
            "== Packages ==\n"
            "Package collection was suppressed by request (--packages suppress).\n",
            encoding="utf-8",
        )
        return

    lines: List[str] = []
    lines.append(f"== Detected family: {family} ==")
    lines.append("")

    core_patterns = load_core_patterns(family)

    def filter_core(full_out: str, fallback_pattern: Optional[re.Pattern] = None) -> List[str]:
        """Return lines matching any of the core patterns, or fallback regex if none defined."""
        all_lines = full_out.splitlines()
        out: List[str] = []

        if core_patterns:
            for line in all_lines:
                for pat in core_patterns:
                    if pat.search(line):
                        out.append(line)
                        break
        elif fallback_pattern is not None:
            for line in all_lines:
                if fallback_pattern.search(line):
                    out.append(line)

        return out

    # Old fallback regex if no external patterns exist at all
    default_core_pattern = re.compile(r"linux|systemd|docker|containerd|kube", re.IGNORECASE)

    if family == "debian":
        if shutil.which("dpkg-query") is None:
            lines.append("dpkg-query not available on this system.")
        else:
            lines.append("== dpkg-query -W ==")
            full_out = run_cmd(["dpkg-query", "-W"])

            if pkg_mode == "verbose":
                lines.append(full_out)
            else:
                core_lines = filter_core(full_out, fallback_pattern=default_core_pattern)
                if core_lines:
                    lines.append("# core packages (pattern-based)")
                    lines.extend(core_lines)
                else:
                    lines.append("# no core packages matched patterns")
            lines.append("")

    elif family == "arch":
        if shutil.which("pacman") is None:
            lines.append("pacman not available on this system.")
        else:
            lines.append("== pacman -Q ==")
            full_out = run_cmd(["pacman", "-Q"])

            if pkg_mode == "verbose":
                lines.append(full_out)
            else:
                core_lines = filter_core(full_out, fallback_pattern=default_core_pattern)
                if core_lines:
                    lines.append("# core packages (pattern-based)")
                    lines.extend(core_lines)
                else:
                    lines.append("# no core packages matched patterns")
            lines.append("")

    elif family in ("rhel", "suse"):
        if shutil.which("rpm") is None:
            lines.append("rpm not available on this system.")
        else:
            lines.append("== rpm -qa ==")
            full_out = run_cmd(["rpm", "-qa"])

            if pkg_mode == "verbose":
                lines.append(full_out)
            else:
                core_lines = filter_core(full_out, fallback_pattern=default_core_pattern)
                if core_lines:
                    lines.append("# core packages (pattern-based)")
                    lines.extend(core_lines)
                else:
                    lines.append("# no core packages matched patterns")
            lines.append("")

    else:
        lines.append("Unknown distro family; package details not collected.")
        lines.append("")

    pkg_file.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Docker JSON helpers for the report
# ---------------------------------------------------------------------------

def run_json_lines(cmd: List[str]) -> List[Dict[str, Any]]:
    """
    Run a docker command that uses --format '{{json .}}' and parse each line.
    Returns a list of dicts (one per line).
    """
    out = run_cmd(cmd)
    results: List[Dict[str, Any]] = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError:
            # ignore junk lines; docker sometimes prints warnings
            continue
    return results


def run_json_single(cmd: List[str]) -> Dict[str, Any]:
    """
    Run a command expected to return a single JSON object.
    Used for `docker version --format '{{json .}}'` and
    `docker info --format '{{json .}}'`.
    """
    out = run_cmd(cmd).strip()
    if not out:
        return {}
    try:
        return json.loads(out.splitlines()[0])
    except json.JSONDecodeError:
        return {}


# ---------------------------------------------------------------------------
# Report builders: each returns a list[str] with Markdown content
# ---------------------------------------------------------------------------

def build_docker_section() -> List[str]:
    """
    Build Markdown for the Docker section:

    - 7.1 Docker engine
    - 7.2 Containers
    - 7.3 Compose projects
    - 7.4 Docker networks
    - 7.5 Docker volumes
    - 7.6 Docker images
    """

    lines: List[str] = []

    # ---------- 7.1 Docker engine ----------
    version_info = run_json_single(["docker", "version", "--format", "{{json .}}"])
    info = run_json_single(["docker", "info", "--format", "{{json .}}"])

    client = version_info.get("Client", {}) or {}
    server = version_info.get("Server", {}) or {}

    lines.append("### 7.1 Docker engine")
    lines.append("")

    ver_rows: List[List[str]] = []
    if client:
        ver_rows.append(
            [
                "Client",
                client.get("Version", ""),
                client.get("ApiVersion", ""),
                client.get("MinAPIVersion", ""),
                client.get("GoVersion", ""),
                f"{client.get('Os', '')}/{client.get('Arch', '')}",
            ]
        )
    if server:
        ver_rows.append(
            [
                "Server",
                server.get("Version", ""),
                server.get("ApiVersion", ""),
                server.get("MinAPIVersion", ""),
                server.get("GoVersion", ""),
                f"{server.get('Os', '')}/{server.get('Arch', '')}",
            ]
        )

    if ver_rows:
        lines.extend(
            md_table(
                ["Role", "Version", "API", "Min API", "Go", "OS/Arch"],
                ver_rows,
            )
        )
    else:
        lines.append(
            "_Docker engine info not available (docker version returned no JSON)._"
        )
        lines.append("")

    if info:
        storage_driver = info.get("Driver", "")
        logging_driver = info.get("LoggingDriver", "")
        cgroup_driver = info.get("CgroupDriver", "")
        default_runtime = info.get("DefaultRuntime", "")
        runtimes = ", ".join(sorted((info.get("Runtimes") or {}).keys()))
        debug_mode = str(info.get("Debug", ""))
        experimental = str(info.get("ExperimentalBuild", ""))

        drv_rows = [
            [
                storage_driver,
                logging_driver,
                cgroup_driver,
                default_runtime,
                runtimes,
                debug_mode,
                experimental,
            ]
        ]
        lines.extend(
            md_table(
                [
                    "Storage driver",
                    "Logging driver",
                    "Cgroup driver",
                    "Default runtime",
                    "Runtimes",
                    "Debug mode",
                    "Experimental",
                ],
                drv_rows,
            )
        )

        reg_cfg = info.get("RegistryConfig", {}) or {}
        insecure = reg_cfg.get("InsecureRegistryCIDRs", []) or []
        mirrors = reg_cfg.get("Mirrors", []) or []

        if insecure or mirrors:
            lines.append("**Registry configuration**")
            lines.append("")
        if insecure:
            lines.append(
                "- Insecure registries (CIDRs this host treats as non-TLS registries):"
            )
            for r in insecure:
                lines.append(f"  - `{r}`")
        if mirrors:
            lines.append("- Registry mirrors:")
            for m in mirrors:
                lines.append(f"  - `{m}`")
        lines.append("")
    else:
        lines.append("_Docker info not available (docker info returned no JSON)._")
        lines.append("")

    # ---------- Collect container list + inspect once ----------
    containers = run_json_lines(
        ["docker", "ps", "--all", "--format", "{{json .}}"]
    )

    inspect_by_name: Dict[str, Dict[str, Any]] = {}
    for c in containers:
        name = c.get("Names")
        if not name:
            continue
        try:
            raw = run_cmd(["docker", "inspect", name])
            obj = json.loads(raw)[0]
            inspect_by_name[name] = obj
        except Exception:
            continue

    # ---------- 7.2 Containers ----------
    lines.append("### 7.2 Containers")
    lines.append("")
    lines.append("_All containers from `docker ps --all` at capture time._")
    lines.append("")
    if containers:
        cont_rows: List[List[str]] = []
        for c in containers:
            cont_rows.append(
                [
                    c.get("Names", ""),
                    c.get("Image", ""),
                    c.get("State", ""),
                    c.get("Status", ""),
                    c.get("Ports", ""),
                    c.get("Networks", ""),
                ]
            )
        lines.extend(
            md_table(
                ["Name", "Image", "State", "Status", "Ports", "Networks"],
                cont_rows,
            )
        )
    else:
        lines.append("No containers (docker ps --all returned no rows).")
        lines.append("")

    # ---------- 7.3 Compose projects ----------
    lines.append("### 7.3 Compose projects")
    lines.append("")
    lines.append("_Compose projects inferred from container labels._")
    lines.append("")
    if containers:
        compose_rows: List[List[str]] = []
        for c in containers:
            name = c.get("Names", "")
            info_obj = inspect_by_name.get(name, {})
            labels = (info_obj.get("Config") or {}).get("Labels", {}) or {}
            project = labels.get("com.docker.compose.project", "")
            cont_id = (info_obj.get("Id", "") or "")[:12]
            compose_rows.append([cont_id, name, project])

        lines.extend(
            md_table(
                ["Container ID", "Name", "Compose project"],
                compose_rows,
            )
        )
    else:
        lines.append("_No Compose projects (no containers to inspect)._")
        lines.append("")

    # ---------- 7.4 Docker networks ----------
    lines.append("### 7.4 Docker networks")
    lines.append("")
    lines.append("_Networks from `docker network ls` + IPAM config._")
    lines.append("")
    networks = run_json_lines(
        ["docker", "network", "ls", "--format", "{{json .}}"]
    )

    if networks:
        net_rows: List[List[str]] = []
        for n in networks:
            name = n.get("Name", "")
            driver = n.get("Driver", "")
            scope = n.get("Scope", "")
            subnet = ""
            gateway = ""
            try:
                cfg_raw = run_cmd(
                    [
                        "docker",
                        "network",
                        "inspect",
                        name,
                        "--format",
                        "{{json .IPAM.Config}}",
                    ]
                )
                cfg = json.loads(cfg_raw)
                if isinstance(cfg, list) and cfg:
                    subnet = cfg[0].get("Subnet", "") or ""
                    gateway = cfg[0].get("Gateway", "") or ""
            except Exception:
                pass
            net_rows.append([name, driver, scope, subnet, gateway])

        lines.extend(
            md_table(
                ["Name", "Driver", "Scope", "Subnet", "Gateway"],
                net_rows,
            )
        )
    else:
        lines.append("_No Docker networks (docker network ls returned no rows)._")
        lines.append("")

    # ---------- 7.5 Docker volumes ----------
    lines.append("### 7.5 Docker volumes")
    lines.append("")
    lines.append("_Named volumes from `docker volume ls`._")
    lines.append("")
    volumes = run_json_lines(
        ["docker", "volume", "ls", "--format", "{{json .}}"]
    )

    if volumes:
        vol_rows: List[List[str]] = []
        for v in volumes:
            name = v.get("Name", "")
            driver = v.get("Driver", "")
            scope = v.get("Scope", "")
            mountpoint = ""
            try:
                mountpoint = run_cmd(
                    [
                        "docker",
                        "volume",
                        "inspect",
                        name,
                        "--format",
                        "{{.Mountpoint}}",
                    ]
                ).strip()
            except Exception:
                pass
            vol_rows.append([name, driver, scope, mountpoint])

        lines.extend(
            md_table(
                ["Name", "Driver", "Scope", "Mountpoint"],
                vol_rows,
            )
        )
    else:
        lines.append("_No named Docker volumes (docker volume ls returned no rows)._")
        lines.append("")

    # ---------- 7.6 Docker images ----------
    lines.append("### 7.6 Docker images")
    lines.append("")
    images = run_json_lines(
        ["docker", "images", "--format", "{{json .}}"]
    )

    if images:
        img_rows: List[List[str]] = []
        for img in images:
            img_rows.append(
                [
                    img.get("Repository", ""),
                    img.get("Tag", ""),
                    img.get("ID", ""),
                    img.get("Size", ""),
                    img.get("CreatedSince", ""),
                    str(img.get("Containers", "")),
                ]
            )
        lines.extend(
            md_table(
                ["Repository", "Tag", "ID", "Size", "CreatedSince", "Containers using"],
                img_rows,
            )
        )
    else:
        lines.append("_No Docker images (docker images returned no rows)._")
        lines.append("")

    return lines


def build_firewall_section() -> List[str]:
    """
    Build Markdown for the firewall section:

    - 5.1 iptables (IPv4)
    - 5.2 ip6tables (IPv6)
    - 5.3 nftables ruleset
    - 5.4 UFW status
    """

    lines: List[str] = []

    # ---------- inner helper: parse iptables/ip6tables output ----------
    def parse_iptables_output(text: str) -> Dict[str, Dict[str, Any]]:
        """
        Parse `iptables -L -n -v` style output into:

        {
          "CHAIN_NAME": {
             "name": ...,
             "policy": ...,
             "pkts": ...,
             "bytes": ...,
             "rules": [
                {
                  "pkts": ..., "bytes": ..., "target": ...,
                  "prot": ..., "opt": ..., "in": ..., "out": ...,
                  "source": ..., "destination": ..., "extra": ...
                },
                ...
             ]
          },
          ...
        }
        """
        chains: Dict[str, Dict[str, Any]] = {}
        current_chain: Optional[Dict[str, Any]] = None

        for ln in text.splitlines():
            ln = ln.rstrip("\n")

            # Chain header
            if ln.startswith("Chain "):
                m = re.match(r"Chain (\S+) \((.+)\)", ln)
                if not m:
                    current_chain = None
                    continue

                name, contents = m.groups()
                pol = pkts = b = None
                m2 = re.search(r"policy (\S+) (\S+) packets, (\S+) bytes", contents)
                if m2:
                    pol, pkts, b = m2.groups()

                current_chain = {
                    "name": name,
                    "policy": pol,
                    "pkts": pkts,
                    "bytes": b,
                    "rules": [],
                }
                chains[name] = current_chain
                continue

            if current_chain is None:
                continue
            if not ln.strip():
                continue
            if ln.lstrip().startswith("pkts "):
                continue

            parts = ln.split()
            if len(parts) < 9:
                continue

            pkts, b, target, prot, opt, in_if, out_if, src, dst = parts[:9]
            extra = " ".join(parts[9:]) if len(parts) > 9 else ""
            current_chain["rules"].append(
                {
                    "pkts": pkts,
                    "bytes": b,
                    "target": target,
                    "prot": prot,
                    "opt": opt,
                    "in": in_if,
                    "out": out_if,
                    "source": src,
                    "destination": dst,
                    "extra": extra,
                }
            )

        return chains

    # Section intro paragraph (top-level heading is added by the caller)
    lines.append(
        "This section summarizes host firewalls and packet filters. "
        "It’s compact enough for an LLM to reason about policies without "
        "wading through full `iptables` dumps."
    )
    lines.append("")

    # ---------- 5.1 iptables (IPv4) ----------
    lines.append("### 5.1 iptables (IPv4)")
    lines.append("")

    try:
        ipt_raw = run_cmd(["iptables", "-L", "-n", "-v"])
        ipt = parse_iptables_output(ipt_raw) if ipt_raw.strip() else {}
    except Exception:
        ipt = {}

    if not ipt:
        lines.append("_iptables output was not available or could not be parsed._")
        lines.append("")
    else:
        # Default chain policies
        lines.append("**Default IPv4 chain policies**")
        lines.append("")
        policy_rows: List[List[str]] = []
        for chain_name in ("INPUT", "FORWARD", "OUTPUT"):
            ch = ipt.get(chain_name)
            if not ch:
                continue
            policy_rows.append(
                [
                    chain_name,
                    ch.get("policy") or "",
                    ch.get("pkts") or "",
                    ch.get("bytes") or "",
                    ]
            )
        if policy_rows:
            lines.extend(
                md_table(
                    ["Chain", "Policy", "Packets", "Bytes"],
                    policy_rows,
                )
            )
        else:
            lines.append("_(No default IPv4 chain policies found in iptables output.)_")
            lines.append("")

        # FORWARD rules (usually where Docker / bridge routing happens)
        fwd = ipt.get("FORWARD")
        if fwd and fwd["rules"]:
            lines.append("")
            lines.append("**FORWARD chain rules (IPv4)**")
            lines.append("")
            fwd_rows: List[List[str]] = []
            for r in fwd["rules"]:
                fwd_rows.append(
                    [
                        r["pkts"],
                        r["bytes"],
                        r["target"],
                        r["in"],
                        r["out"],
                        r["source"],
                        r["destination"],
                        r["extra"],
                    ]
                )
            lines.extend(
                md_table(
                    [
                        "Pkts",
                        "Bytes",
                        "Target",
                        "In",
                        "Out",
                        "Source",
                        "Destination",
                        "Match/Extra",
                    ],
                    fwd_rows,
                )
            )

        # Docker chains
        docker_chains = [ch for name, ch in ipt.items() if name.startswith("DOCKER")]
        if docker_chains:
            lines.append("")
            lines.append("**Docker-related chains (IPv4)**")
            lines.append("")
            d_rows: List[List[str]] = []
            for ch in sorted(docker_chains, key=lambda c: c["name"]):
                for r in ch["rules"]:
                    d_rows.append(
                        [
                            ch["name"],
                            r["target"],
                            r["in"],
                            r["out"],
                            r["source"],
                            r["destination"],
                            r["extra"],
                        ]
                    )
            lines.extend(
                md_table(
                    ["Chain", "Target", "In", "Out", "Source", "Destination", "Match/Extra"],
                    d_rows,
                )
            )
        lines.append("")

    # ---------- 5.2 ip6tables (IPv6) ----------
    lines.append("### 5.2 ip6tables (IPv6)")
    lines.append("")

    try:
        ip6_raw = run_cmd(["ip6tables", "-L", "-n", "-v"])
        ip6 = parse_iptables_output(ip6_raw) if ip6_raw.strip() else {}
    except Exception:
        ip6 = {}

    if not ip6:
        lines.append("_ip6tables output was not available or could not be parsed._")
        lines.append("")
    else:
        lines.append("**Default IPv6 chain policies**")
        lines.append("")
        policy6_rows: List[List[str]] = []
        for chain_name in ("INPUT", "FORWARD", "OUTPUT"):
            ch = ip6.get(chain_name)
            if not ch:
                continue
            policy6_rows.append(
                [
                    chain_name,
                    ch.get("policy") or "",
                    ch.get("pkts") or "",
                    ch.get("bytes") or "",
                    ]
            )
        if policy6_rows:
            lines.extend(
                md_table(
                    ["Chain", "Policy", "Packets", "Bytes"],
                    policy6_rows,
                )
            )
        else:
            lines.append("_(No default IPv6 chain policies found in ip6tables output.)_")
            lines.append("")

        docker6_chains = [ch for name, ch in ip6.items() if name.startswith("DOCKER")]
        if docker6_chains:
            lines.append("")
            lines.append("**Docker-related chains (IPv6)**")
            lines.append("")
            d6_rows: List[List[str]] = []
            for ch in sorted(docker6_chains, key=lambda c: c["name"]):
                for r in ch["rules"]:
                    d6_rows.append(
                        [
                            ch["name"],
                            r["target"],
                            r["in"],
                            r["out"],
                            r["source"],
                            r["destination"],
                            r["extra"],
                        ]
                    )
            lines.extend(
                md_table(
                    ["Chain", "Target", "In", "Out", "Source", "Destination", "Match/Extra"],
                    d6_rows,
                )
            )
        lines.append("")

    # ---------- 5.3 nftables ----------
    lines.append("### 5.3 nftables ruleset")
    lines.append("")

    try:
        nft_raw = run_cmd(["nft", "list", "ruleset"])
    except Exception:
        nft_raw = ""

    nft_raw = nft_raw.strip()
    if nft_raw:
        lines.append("Raw `nft list ruleset` output:")
        lines.append("")
        lines.append("```text")
        lines.extend(nft_raw.splitlines())
        lines.append("```")
        lines.append("")
    else:
        lines.append("_`nft` is not installed or `nft list ruleset` returned nothing._")
        lines.append("")

    # ---------- 5.4 UFW ----------
    lines.append("### 5.4 UFW status")
    lines.append("")

    try:
        ufw_raw = run_cmd(["ufw", "status", "verbose"])
    except Exception:
        ufw_raw = ""

    ufw_raw = (ufw_raw or "").strip()

    if not ufw_raw or "command not available" in ufw_raw.lower():
        lines.append("_UFW is not installed or `ufw status verbose` returned nothing._")
        lines.append("")
    else:
        lines.append("Raw `ufw status verbose` output:")
        lines.append("")
        lines.append("```text")
        lines.extend(ufw_raw.splitlines())
        lines.append("```")
        lines.append("")

    lines.append(
        "_Note: if you also persist a raw firewall dump (e.g. `05-firewall.txt`), "
        "that can be used for deeper, non-LLM analysis._"
    )
    lines.append("")

    return lines


def build_os_section() -> List[str]:
    """
    Build Markdown for the OS section:

    - 2.1 Basic OS summary
    - 2.2 Kernel & libc
    - 2.3 Hardware summary
    - 2.4 Distro metadata (os-release, lsb_release, arch marker, etc.)
    """

    lines: List[str] = []

    def _parse_hostnamectl(raw: str) -> Dict[str, str]:
        info: Dict[str, str] = {}
        for ln in raw.splitlines():
            if ":" not in ln:
                continue
            key, val = ln.split(":", 1)
            info[key.strip()] = val.strip()
        return info

    def _read_os_release() -> Dict[str, str]:
        path = "/etc/os-release"
        if not os.path.exists(path):
            return {}
        data: Dict[str, str] = {}
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for ln in f:
                    ln = ln.strip()
                    if not ln or ln.startswith("#") or "=" not in ln:
                        continue
                    k, v = ln.split("=", 1)
                    k = k.strip()
                    v = v.strip()
                    if len(v) >= 2 and v[0] == v[-1] == '"':
                        v = v[1:-1]
                    data[k] = v
        except Exception:
            return {}
        return data

    # ----------------- collect raw data -----------------

    uname_a = safe_cmd(["uname", "-a"])
    uname_r = safe_cmd(["uname", "-r"])
    uname_m = safe_cmd(["uname", "-m"])

    hostnamectl_raw = safe_cmd(["hostnamectl"])
    hostname_info = _parse_hostnamectl(hostnamectl_raw) if hostnamectl_raw else {}

    os_release = _read_os_release()

    lsb_raw = safe_cmd(["lsb_release", "-a"])
    ldd_raw = safe_cmd(["ldd", "--version"])
    ldd_first = ldd_raw.splitlines()[0].strip() if ldd_raw else ""

    arch_marker = ""
    if os.path.exists("/etc/arch-release"):
        try:
            with open("/etc/arch-release", "r", encoding="utf-8", errors="ignore") as f:
                content = f.read().strip()
            if content:
                arch_marker = content
            else:
                arch_marker = "(present but empty marker file)"
        except Exception:
            arch_marker = "(present but unreadable)"

    # Intro (top-level heading is added by the caller)
    lines.append(
        "High-level OS and distro details: enough for an LLM to understand "
        "what it’s looking at without drowning in every env-specific ID."
    )
    lines.append("")

    # 2.1 Basic OS summary
    lines.append("### 2.1 Basic OS summary")
    lines.append("")

    os_name = os_release.get("PRETTY_NAME") or hostname_info.get("Operating System", "")
    distro_id = os_release.get("ID", "")
    distro_like = os_release.get("ID_LIKE", "")

    os_rows: List[List[str]] = [
        [
            os_name or "(unknown)",
            uname_r or "(unknown)",
            uname_m or "(unknown)",
            distro_id or "",
            distro_like or "",
            ]
    ]
    lines.extend(
        md_table(
            ["OS", "Kernel", "Arch", "Distro ID", "ID_LIKE"],
            os_rows,
        )
    )
    lines.append("")

    # 2.2 Kernel & libc
    lines.append("### 2.2 Kernel and libc")
    lines.append("")
    kern_rows: List[List[str]] = [
        [uname_r or "(unknown)", ldd_first or "(ldd not available)"]
    ]
    lines.extend(
        md_table(
            ["Kernel release", "libc (ldd --version, first line)"],
            kern_rows,
        )
    )
    lines.append("")

    # 2.3 Hardware summary (non-identifying)
    lines.append("### 2.3 Hardware summary")
    lines.append("")

    vendor = hostname_info.get("Hardware Vendor", "")
    model = hostname_info.get("Hardware Model", "")
    fw_ver = hostname_info.get("Firmware Version", "")
    fw_date = hostname_info.get("Firmware Date", "")

    if vendor or model or fw_ver or fw_date:
        hw_rows: List[List[str]] = [
            [vendor or "", model or "", fw_ver or "", fw_date or ""]
        ]
        lines.extend(
            md_table(
                ["Vendor", "Model", "Firmware version", "Firmware date"],
                hw_rows,
            )
        )
        lines.append("")
    else:
        lines.append("_`hostnamectl` did not return hardware details on this host._")
        lines.append("")

    # 2.4 Distro metadata / raw blocks
    lines.append("### 2.4 Distro metadata and raw OS info")
    lines.append("")

    if os_release:
        lines.append("**/etc/os-release**")
        lines.append("")
        lines.append("```ini")
        for k in sorted(os_release.keys()):
            v = os_release[k]
            if " " in v or ";" in v:
                v_out = f'"{v}"'
            else:
                v_out = v
            lines.append(f"{k}={v_out}")
        lines.append("```")
        lines.append("")
    else:
        lines.append("_`/etc/os-release` not found or unreadable._")
        lines.append("")

    if lsb_raw:
        lines.append("**`lsb_release -a`**")
        lines.append("")
        lines.append("```text")
        lines.extend(lsb_raw.splitlines())
        lines.append("```")
        lines.append("")
    else:
        lines.append("_`lsb_release` is not installed or returned nothing._")
        lines.append("")

    if arch_marker:
        lines.append("**Arch-specific marker**")
        lines.append("")
        lines.append("```text")
        lines.append("/etc/arch-release")
        lines.append(arch_marker)
        lines.append("```")
        lines.append("")

    if uname_a:
        lines.append("**Raw `uname -a`**")
        lines.append("")
        lines.append("```text")
        lines.append(uname_a)
        lines.append("```")
        lines.append("")

    lines.append(
        "_Note: host-specific identifiers (Machine ID, Boot ID, UUIDs, serials) "
        "are intentionally omitted from this summary; keep raw `02-os.txt` private if present._"
    )
    lines.append("")

    return lines


def build_network_section() -> List[str]:
    """
    Build Markdown for the network section:

    - 4.1 Interface summary (ip -br addr)
    - 4.2 IPv4 routing table (ip route)
    - 4.3 IPv6 routing table (ip -6 route)
    - 4.4 DNS configuration (resolv.conf)
    - 4.5 Listening sockets (ss -lntu)
    """

    lines: List[str] = []

    def _parse_ip_br_addr(raw: str) -> List[Dict[str, Any]]:
        """
        Parse `ip -br addr` into:
        [
          {
            "ifname": "...",
            "state": "...",
            "ipv4": ["addr/len", ...],
            "ipv6": ["addr/len", ...],
          },
          ...
        ]
        """
        results: List[Dict[str, Any]] = []
        for ln in raw.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            parts = ln.split()
            if len(parts) < 2:
                continue
            ifname = parts[0]
            state = parts[1]
            addrs = parts[2:]

            v4_list: List[str] = []
            v6_list: List[str] = []
            for a in addrs:
                if "/" not in a:
                    continue
                if ":" in a:
                    v6_list.append(a)
                else:
                    v4_list.append(a)

            results.append(
                {
                    "ifname": ifname,
                    "state": state,
                    "ipv4": v4_list,
                    "ipv6": v6_list,
                }
            )
        return results

    def _parse_ip_route(raw: str) -> List[Dict[str, Any]]:
        """
        Parse `ip route` into a list of dicts:
        { "dest": ..., "via": ..., "dev": ..., "src": ..., "extra": ... }
        """
        routes: List[Dict[str, Any]] = []
        for ln in raw.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            parts = ln.split()
            dest = parts[0]
            via = ""
            dev = ""
            src = ""
            extra_parts: List[str] = []

            i = 1
            while i < len(parts):
                tok = parts[i]
                if tok == "via" and i + 1 < len(parts):
                    via = parts[i + 1]
                    i += 2
                    continue
                if tok == "dev" and i + 1 < len(parts):
                    dev = parts[i + 1]
                    i += 2
                    continue
                if tok == "src" and i + 1 < len(parts):
                    src = parts[i + 1]
                    i += 2
                    continue
                extra_parts.append(tok)
                i += 1

            routes.append(
                {
                    "dest": dest,
                    "via": via,
                    "dev": dev,
                    "src": src,
                    "extra": " ".join(extra_parts),
                }
            )
        return routes

    def _parse_ip6_route(raw: str) -> List[Dict[str, Any]]:
        """
        Parse `ip -6 route` into:
        { "dest": ..., "dev": ..., "metric": ..., "extra": ... }
        """
        routes: List[Dict[str, Any]] = []
        for ln in raw.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            parts = ln.split()
            dest = parts[0]
            dev = ""
            metric = ""
            extra_parts: List[str] = []

            i = 1
            while i < len(parts):
                tok = parts[i]
                if tok == "dev" and i + 1 < len(parts):
                    dev = parts[i + 1]
                    i += 2
                    continue
                if tok == "metric" and i + 1 < len(parts):
                    metric = parts[i + 1]
                    i += 2
                    continue
                extra_parts.append(tok)
                i += 1

            routes.append(
                {
                    "dest": dest,
                    "dev": dev,
                    "metric": metric,
                    "extra": " ".join(extra_parts),
                }
            )
        return routes

    def _parse_resolv_conf(path: str = "/etc/resolv.conf") -> Dict[str, List[str]]:
        """
        Parse resolv.conf into { 'search': [...], 'nameservers': [...] }.
        """
        cfg: Dict[str, List[str]] = {"search": [], "nameservers": []}
        if not os.path.exists(path):
            return cfg
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for ln in f:
                    ln = ln.strip()
                    if not ln or ln.startswith("#"):
                        continue
                    if ln.startswith("search "):
                        parts = ln.split()
                        cfg["search"].extend(parts[1:])
                    elif ln.startswith("nameserver "):
                        parts = ln.split()
                        if len(parts) >= 2:
                            cfg["nameservers"].append(parts[1])
        except Exception:
            pass
        return cfg

    # ----------------- collect raw data -----------------

    ip_br_raw = safe_cmd(["ip", "-br", "addr"])
    ip4_route_raw = safe_cmd(["ip", "route"])
    ip6_route_raw = safe_cmd(["ip", "-6", "route"])
    ss_raw = safe_cmd(["ss", "-lntu"])
    resolv_cfg = _parse_resolv_conf()

    ifaces = _parse_ip_br_addr(ip_br_raw) if ip_br_raw else []
    ip4_routes = _parse_ip_route(ip4_route_raw) if ip4_route_raw else []
    ip6_routes = _parse_ip6_route(ip6_route_raw) if ip6_route_raw else []

    # Intro
    lines.append(
        "Host-level network view: interfaces, routes, DNS, and listening sockets. "
        "Enough for an LLM to understand traffic paths, Docker bridges, and exposed "
        "ports without dumping every connection."
    )
    lines.append("")

    # 4.1 Interface summary
    lines.append("### 4.1 Interface summary")
    lines.append("")
    if not ifaces:
        lines.append("_`ip -br addr` is not available or returned nothing._")
        lines.append("")
    else:
        rows: List[List[str]] = []
        for iface in ifaces:
            rows.append(
                [
                    iface["ifname"],
                    iface["state"],
                    ", ".join(iface["ipv4"]) or "",
                    ", ".join(iface["ipv6"]) or "",
                    ]
            )
        lines.extend(
            md_table(
                ["Interface", "State", "IPv4 addresses", "IPv6 addresses"],
                rows,
            )
        )
        lines.append("")

    # 4.2 IPv4 routing table
    lines.append("### 4.2 IPv4 routing table")
    lines.append("")
    if not ip4_routes:
        lines.append("_`ip route` is not available or returned nothing._")
        lines.append("")
    else:
        rows = []
        for r in ip4_routes:
            rows.append(
                [
                    r["dest"],
                    r["via"],
                    r["dev"],
                    r["src"],
                    r["extra"],
                ]
            )
        lines.extend(
            md_table(
                ["Destination", "Gateway", "Dev", "Src", "Extra"],
                rows,
            )
        )
        lines.append("")

    # 4.3 IPv6 routing table
    lines.append("### 4.3 IPv6 routing table")
    lines.append("")
    if not ip6_routes:
        lines.append("_`ip -6 route` is not available or returned nothing._")
        lines.append("")
    else:
        rows = []
        for r in ip6_routes:
            rows.append(
                [
                    r["dest"],
                    r["dev"],
                    r["metric"],
                    r["extra"],
                ]
            )
        lines.extend(
            md_table(
                ["Destination", "Dev", "Metric", "Extra"],
                rows,
            )
        )
        lines.append("")

    # 4.4 DNS configuration
    lines.append("### 4.4 DNS configuration")
    lines.append("")

    search_list = resolv_cfg.get("search", [])
    ns_list = resolv_cfg.get("nameservers", [])

    if not search_list and not ns_list:
        lines.append("_No resolv.conf search domains or nameservers found._")
        lines.append("")
    else:
        rows = [[", ".join(search_list) or "", ", ".join(ns_list) or ""]]
        lines.extend(
            md_table(
                ["Search domains", "Nameservers"],
                rows,
            )
        )
        lines.append("")

    # 4.5 Listening sockets
    lines.append("### 4.5 Listening sockets (ss -lntu)")
    lines.append("")
    if not ss_raw:
        lines.append("_`ss -lntu` is not available or returned nothing._")
        lines.append("")
    else:
        lines.append(
            "Summary of listening TCP/UDP sockets from `ss -lntu`. This gives a quick "
            "view of exposed ports and local listeners without dumping connection "
            "state for every flow."
        )
        lines.append("")
        lines.append("```text")
        lines.extend(ss_raw.splitlines())
        lines.append("```")
        lines.append("")

    lines.append(
        "_Note: for full raw dumps (including command banners), "
        "keep `04-network.txt` alongside this report if needed._"
    )
    lines.append("")

    return lines


def build_hardware_section() -> List[str]:
    """
    Build Markdown for the hardware section:

    - 3.1 CPU summary (lscpu)
    - 3.2 Memory (free -h)
    - 3.3 Block devices (lsblk)
    - 3.4 Filesystems (df -h)
    """

    lines: List[str] = []

    def _parse_lscpu(raw: str) -> Dict[str, str]:
        info: Dict[str, str] = {}
        for ln in raw.splitlines():
            if ":" not in ln:
                continue
            key, val = ln.split(":", 1)
            info[key.strip()] = val.strip()
        return info

    def _parse_free(raw: str) -> Dict[str, Dict[str, str]]:
        mem: Dict[str, str] = {}
        swap: Dict[str, str] = {}
        lines_local = [ln.strip() for ln in raw.splitlines() if ln.strip()]
        if len(lines_local) < 2:
            return {"mem": mem, "swap": swap}

        headers = lines_local[0].split()
        mem_line = None
        swap_line = None
        for ln in lines_local[1:]:
            parts = ln.split()
            if not parts:
                continue
            label = parts[0].rstrip(":")
            values = parts[1:]
            if label.lower() == "mem":
                mem_line = values
            elif label.lower() == "swap":
                swap_line = values

        def _mk_map(vals: Optional[List[str]]) -> Dict[str, str]:
            if not vals:
                return {}
            m: Dict[str, str] = {}
            for i, h in enumerate(headers):
                if i < len(vals):
                    m[h.lower()] = vals[i]
            return m

        mem = _mk_map(mem_line)
        swap = _mk_map(swap_line)

        return {"mem": mem, "swap": swap}

    def _parse_lsblk_pairs(raw: str) -> List[Dict[str, str]]:
        rows: List[Dict[str, str]] = []
        for ln in raw.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            entry: Dict[str, str] = {}
            for m in re.finditer(r'(\w+)="([^"]*)"', ln):
                key = m.group(1).lower()
                val = m.group(2)
                entry[key] = val
            if entry:
                rows.append(entry)
        return rows

    def _parse_df(raw: str) -> List[Dict[str, str]]:
        rows: List[Dict[str, str]] = []
        lines_local = [ln.rstrip() for ln in raw.splitlines() if ln.strip()]
        if len(lines_local) < 2:
            return rows

        for ln in lines_local[1:]:
            parts = ln.split()
            if len(parts) < 6:
                continue
            filesystem = parts[0]
            size = parts[1]
            used = parts[2]
            avail = parts[3]
            usep = parts[4]
            mountpoint = " ".join(parts[5:])
            rows.append(
                {
                    "filesystem": filesystem,
                    "size": size,
                    "used": used,
                    "avail": avail,
                    "use%": usep,
                    "mountpoint": mountpoint,
                }
            )
        return rows

    # ----------------- collect raw data -----------------

    lscpu_raw = safe_cmd(["lscpu"])
    free_raw = safe_cmd(["free", "-h"])
    lsblk_raw = safe_cmd(
        [
            "lsblk",
            "-P",
            "-o",
            "NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,MODEL,PKNAME,TRAN,ROTA",
        ]
    )
    df_raw = safe_cmd(["df", "-h"])

    cpu_info = _parse_lscpu(lscpu_raw) if lscpu_raw else {}
    mem_info = _parse_free(free_raw) if free_raw else {"mem": {}, "swap": {}}
    blk_rows = _parse_lsblk_pairs(lsblk_raw) if lsblk_raw else []
    df_rows = _parse_df(df_raw) if df_raw else []

    # Intro
    lines.append(
        "Physical and logical hardware layout: CPU, memory, block devices and filesystems. "
        "This is the layer where performance bottlenecks and capacity constraints usually start."
    )
    lines.append("")

    # 3.1 CPU summary
    lines.append("### 3.1 CPU summary")
    lines.append("")
    if not cpu_info:
        lines.append("_`lscpu` is not available or returned nothing._")
        lines.append("")
    else:
        model = cpu_info.get("Model name", "")
        arch = cpu_info.get("Architecture", "")
        sockets = cpu_info.get("Socket(s)", "")
        cores_per_socket = cpu_info.get("Core(s) per socket", "")
        threads_per_core = cpu_info.get("Thread(s) per core", "")
        logical = cpu_info.get("CPU(s)", "")
        max_mhz = cpu_info.get("CPU max MHz", "")
        min_mhz = cpu_info.get("CPU min MHz", "")
        virt = cpu_info.get("Virtualization", "")

        rows = [
            [
                model,
                arch,
                sockets,
                cores_per_socket,
                threads_per_core,
                logical,
                max_mhz,
                min_mhz,
                virt,
            ]
        ]
        lines.extend(
            md_table(
                [
                    "Model",
                    "Arch",
                    "Sockets",
                    "Cores / socket",
                    "Threads / core",
                    "Logical CPUs",
                    "Max MHz",
                    "Min MHz",
                    "Virtualization",
                ],
                rows,
            )
        )
        lines.append("")

    # 3.2 Memory summary
    lines.append("### 3.2 Memory")
    lines.append("")
    mem = mem_info.get("mem", {})
    swap = mem_info.get("swap", {})

    if not mem and not swap:
        lines.append("_`free -h` is not available or returned nothing._")
        lines.append("")
    else:
        # RAM
        mem_row = [
            mem.get("total", ""),
            mem.get("used", ""),
            mem.get("free", ""),
            mem.get("shared", ""),
            mem.get("buff/cache", mem.get("buff/cache".lower(), "")),
            mem.get("available", ""),
        ]
        lines.append("#### 3.2.1 RAM")
        lines.append("")
        lines.extend(
            md_table(
                ["Total", "Used", "Free", "Shared", "Buff/cache", "Available"],
                [mem_row],
            )
        )
        lines.append("")

        # Swap
        lines.append("#### 3.2.2 Swap")
        lines.append("")
        if not swap:
            lines.append("_No swap information reported (swap may be disabled)._")
            lines.append("")
        else:
            swap_row = [
                swap.get("total", ""),
                swap.get("used", ""),
                swap.get("free", ""),
            ]
            lines.extend(
                md_table(
                    ["Total", "Used", "Free"],
                    [swap_row],
                )
            )
            lines.append("")

    # 3.3 Block devices
    lines.append("### 3.3 Block devices")
    lines.append("")
    lines.append(
        "Physical disks and their logical children (partitions, encrypted volumes). "
        "Parent/child relationships are explicit via the 'Parent' column."
    )
    lines.append("")

    if not blk_rows:
        lines.append("_`lsblk` is not available or returned nothing._")
        lines.append("")
    else:
        disks: List[Dict[str, str]] = []
        children: List[Dict[str, str]] = []

        for r in blk_rows:
            r_type = r.get("type", "")
            if r_type == "disk":
                disks.append(r)
            else:
                if r_type == "loop":
                    continue
                children.append(r)

        # 3.3.1 Physical block devices
        lines.append("#### 3.3.1 Physical disks")
        lines.append("")
        if not disks:
            lines.append("_No physical disks reported by `lsblk`._")
            lines.append("")
        else:
            disk_rows: List[List[str]] = []
            for d in disks:
                name = d.get("name", "")
                d_type = d.get("type", "")
                size = d.get("size", "")
                model = d.get("model", "")
                tran = d.get("tran", "")
                rota = d.get("rota", "")
                if rota == "0":
                    rota_h = "no"
                elif rota == "1":
                    rota_h = "yes"
                else:
                    rota_h = rota
                disk_rows.append(
                    [name, d_type, size, tran, rota_h, model]
                )

            lines.extend(
                md_table(
                    ["Name", "Type", "Size", "Transport", "Rotational", "Model"],
                    disk_rows,
                )
            )
            lines.append("")

        # 3.3.2 Logical volumes / partitions
        lines.append("#### 3.3.2 Logical volumes and partitions")
        lines.append("")
        if not children:
            lines.append("_No partitions or logical volumes reported by `lsblk`._")
            lines.append("")
        else:
            child_rows: List[List[str]] = []
            for c in children:
                name = c.get("name", "")
                parent = c.get("pkname", "")
                c_type = c.get("type", "")
                size = c.get("size", "")
                fstype = c.get("fstype", "")
                mnt = c.get("mountpoint", "")
                child_rows.append(
                    [name, parent, c_type, size, fstype, mnt]
                )

            lines.extend(
                md_table(
                    ["Name", "Parent", "Type", "Size", "Fstype", "Mountpoint"],
                    child_rows,
                )
            )
            lines.append("")

    # 3.4 Filesystem usage
    lines.append("### 3.4 Filesystem usage")
    lines.append("")
    lines.append(
        "Mounted filesystems and utilization. Overlay entries from Docker are "
        "kept so an LLM can see container storage impact, but can be filtered "
        "out later if you only care about base OS filesystems."
    )
    lines.append("")

    if not df_rows:
        lines.append("_`df -h` is not available or returned nothing._")
        lines.append("")
    else:
        table_rows: List[List[str]] = []
        for r in df_rows:
            table_rows.append(
                [
                    r.get("filesystem", ""),
                    r.get("size", ""),
                    r.get("used", ""),
                    r.get("avail", ""),
                    r.get("use%", ""),
                    r.get("mountpoint", ""),
                ]
            )

        lines.extend(
            md_table(
                ["Filesystem", "Size", "Used", "Avail", "Use%", "Mountpoint"],
                table_rows,
            )
        )
        lines.append("")

    lines.append(
        "_Note: for full raw command output, keep `03-hardware.txt` beside this report. "
        "The tables here are deliberately trimmed for LLM analysis._"
    )
    lines.append("")

    return lines


def build_services_section() -> List[str]:
    """
    Section 6: system services (systemd).

    Summarizes systemd services grouped by sub-state:
    - running
    - exited/dead
    - failed
    """
    lines: List[str] = []

    def _safe_systemctl(args: List[str]) -> str:
        return safe_cmd(args)

    def _parse_systemctl_list(raw: str) -> List[Dict[str, str]]:
        """
        Parse `systemctl ...` output into:
        { "unit": ..., "load": ..., "active": ..., "sub": ..., "description": ... }
        """
        rows: List[Dict[str, str]] = []
        if not raw:
            return rows

        for ln in raw.splitlines():
            ln = ln.rstrip()
            if not ln:
                continue

            s = ln.lstrip()
            if s.startswith("UNIT "):
                continue
            if s.startswith("LOAD "):
                continue
            if s.startswith("LIST "):
                continue
            if s.startswith("Legend:"):
                break
            if "loaded units listed" in s:
                break

            parts = ln.split(None, 4)
            if not parts:
                continue

            if parts[0] in ("●", "○", "*"):
                stripped = ln.lstrip("●○* ").rstrip()
                parts = stripped.split(None, 4)

            if len(parts) < 5:
                continue

            unit, load, active, sub, desc = parts
            rows.append(
                {
                    "unit": unit,
                    "load": load,
                    "active": active,
                    "sub": sub,
                    "description": desc,
                }
            )
        return rows

    # Intro
    lines.append(
        "Systemd service state for this host, grouped by sub-state. This helps an LLM "
        "see what is currently running, what has exited cleanly, and what is failed."
    )
    lines.append("")

    svc_raw = _safe_systemctl(
        ["systemctl", "list-units", "--type=service", "--no-pager"]
    )

    if not svc_raw:
        lines.append("### 6.1 Running services (systemd)")
        lines.append("")
        lines.append(
            "_`systemctl` is not available or this system is not using systemd; "
            "skipping service listing._"
        )
        lines.append("")
        lines.append("### 6.2 Exited services (systemd)")
        lines.append("")
        lines.append(
            "_`systemctl` is not available or this system is not using systemd; "
            "skipping service listing._"
        )
        lines.append("")
        lines.append("### 6.3 Failed services (systemd)")
        lines.append("")
        lines.append(
            "_`systemctl` is not available or this system is not using systemd; "
            "skipping service listing._"
        )
        lines.append("")
        return lines

    svc_rows = _parse_systemctl_list(svc_raw)

    running_rows = [r for r in svc_rows if r.get("sub") == "running"]
    exited_rows = [r for r in svc_rows if r.get("sub") in ("exited", "dead")]
    main_failed_rows = [r for r in svc_rows if r.get("sub") == "failed"]

    # 6.1 Running
    lines.append("### 6.1 Running services (systemd)")
    lines.append("")
    if not running_rows:
        lines.append("_No services with sub-state `running` at the time of capture._")
        lines.append("")
    else:
        lines.append(
            "Services that are currently running (sub-state `running`)."
        )
        lines.append("")
        table_rows: List[List[str]] = []
        for r in running_rows:
            table_rows.append(
                [
                    r.get("unit", ""),
                    r.get("sub", ""),
                    r.get("description", ""),
                ]
            )
        lines.extend(md_table(["Unit", "Sub", "Description"], table_rows))
        lines.append("")

    # 6.2 Exited
    lines.append("### 6.2 Exited services (systemd)")
    lines.append("")
    if not exited_rows:
        lines.append(
            "_No services with sub-state `exited` or `dead` at the time of capture._"
        )
        lines.append("")
    else:
        lines.append(
            "Services that have exited or are marked `dead`. These are often oneshot "
            "units or services that only run at boot."
        )
        lines.append("")
        table_rows = []
        for r in exited_rows:
            table_rows.append(
                [
                    r.get("unit", ""),
                    r.get("sub", ""),
                    r.get("description", ""),
                ]
            )
        lines.extend(md_table(["Unit", "Sub", "Description"], table_rows))
        lines.append("")

    # 6.3 Failed
    lines.append("### 6.3 Failed services (systemd)")
    lines.append("")
    failed_raw = _safe_systemctl(["systemctl", "--failed", "--no-pager"])
    parsed_failed = _parse_systemctl_list(failed_raw)
    failed_by_unit: Dict[str, Dict[str, str]] = {}
    for r in main_failed_rows + parsed_failed:
        unit = r.get("unit")
        if unit:
            failed_by_unit[unit] = r

    failed_rows = list(failed_by_unit.values())

    if not failed_rows:
        lines.append(
            "_No failed units reported by `systemctl` at the time of capture._"
        )
        lines.append("")
    else:
        lines.append(
            "Services that are in a failed state according to `systemctl`. "
            "These typically need investigation or cleanup."
        )
        lines.append("")
        table_rows = []
        for r in failed_rows:
            table_rows.append(
                [
                    r.get("unit", ""),
                    r.get("sub", ""),
                    r.get("description", ""),
                ]
            )
        lines.extend(md_table(["Unit", "Sub", "Description"], table_rows))
        lines.append("")

    return lines


def build_packages_section(pkg_file: Path, pkg_mode: str) -> List[str]:
    """
    Section 8: packages.

    Reads the already-collected 08-packages.txt snapshot and turns the
    "core packages" subset into a compact table. For verbose mode, it
    just explains where the full list lives (to avoid dumping thousands
    of lines into the report).
    """
    lines: List[str] = []

    if pkg_mode == "suppress":
        lines.append(
            "_Package collection was disabled (`--packages suppress`)._"
        )
        lines.append("")
        return lines

    if not pkg_file.exists():
        lines.append(
            f"_Expected package snapshot file `{pkg_file}` does not exist; "
            "no package details are available in this report._"
        )
        lines.append("")
        return lines

    raw_lines = pkg_file.read_text(encoding="utf-8", errors="ignore").splitlines()

    current_pm: Optional[str] = None
    in_core_block = False
    core_rows: List[Tuple[str, str, str]] = []

    for line in raw_lines:
        s = line.strip()
        if not s:
            if in_core_block:
                in_core_block = False
            continue

        if s.startswith("==") and s.endswith("=="):
            label = s.strip("=").strip()
            # ignore the "Detected family" banner as a pseudo-manager
            if label.lower().startswith("detected family"):
                current_pm = None
            else:
                current_pm = label.split()[0]
            in_core_block = False
            continue

        if s.startswith("# core packages"):
            in_core_block = True
            continue

        if s.startswith("#"):
            continue

        if in_core_block and current_pm:
            parts = s.split()
            if not parts:
                continue
            pkg_name = parts[0]
            pkg_ver = " ".join(parts[1:]) if len(parts) > 1 else ""
            core_rows.append((current_pm, pkg_name, pkg_ver))

    lines.append(f"_Package capture mode: `{pkg_mode}`._")
    lines.append("")

    if core_rows:
        lines.append("### 8.1 Core OS / infrastructure packages")
        lines.append("")
        lines.append(
            "Subset of packages considered core to the OS, kernel, container/runtime "
            "stack and base system services. This gives an LLM enough context to "
            "reason about the environment without dumping every installed package."
        )
        lines.append("")

        table_rows: List[List[str]] = [
            [pm, name, ver] for (pm, name, ver) in core_rows
        ]
        lines.extend(
            md_table(
                ["Manager", "Package", "Version / details"],
                table_rows,
            )
        )
        lines.append("")
    else:
        if pkg_mode != "verbose":
            lines.append(
                "_No core package subset was captured in the snapshot file. "
                "The package collector may have been run in a different mode, "
                "or pattern filters matched nothing._"
            )
            lines.append("")

    if pkg_mode == "verbose":
        total_pkg_lines = sum(
            1
            for s in raw_lines
            if s.strip()
            and not s.strip().startswith("#")
            and not (s.strip().startswith("==") and s.strip().endswith("=="))
        )
        lines.append("### 8.2 Full package lists (verbose mode)")
        lines.append("")
        lines.append(
            f"The snapshot captured full package manager output "
            f"({total_pkg_lines} lines) in `{pkg_file.name}`. "
            "To keep this report compact and LLM-friendly, those lists are "
            "not inlined here. Use the raw file if you need every package."
        )
        lines.append("")

    return lines


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def generate_markdown_reports(
        snapshot_dir: Path,
        hostname: str,
        distro_id: str,
        distro_like: str,
        meta_file: Path,
        os_file: Path,
        hw_file: Path,
        net_file: Path,
        fw_file: Path,
        srv_file: Path,
        docker_file: Path,
        pkg_file: Path,
        pkg_mode: str,
        sections: Set[str],
        split_reports: bool,
) -> List[Path]:
    """
    Generate Markdown reports.

    - If split_reports is False: one combined report, filtered by sections.
    - If split_reports is True: one report per section (e.g. network-only),
      filenames include the section name.
    """

    def fenced_text(path: Path) -> str:
        return f"```text\n{path.read_text(encoding='utf-8', errors='ignore')}\n```"

    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

    created: List[Path] = []

    ordered = ["meta", "os", "hardware", "network", "firewall", "services", "docker", "packages"]

    def build_single_section_report(section: str) -> Tuple[str, List[str]]:
        lines: List[str] = []
        title_suffix = section.capitalize()

        lines.append(f"# System Report: {hostname} — {title_suffix}")
        lines.append("")
        lines.append(f"- Snapshot path: `{snapshot_dir}`")
        lines.append(f"- Captured at: `{timestamp}`")
        lines.append(f"- Distro ID: `{distro_id}`")
        lines.append(f"- Distro like: `{distro_like}`")
        lines.append("")

        if section == "meta":
            lines.append("## 1. Snapshot & meta")
            lines.append("")
            lines.append(fenced_text(meta_file))

        elif section == "os":
            lines.append("## 2. Operating system")
            lines.append("")
            lines.extend(build_os_section())

        elif section == "hardware":
            lines.append("## 3. Hardware and storage")
            lines.append("")
            lines.extend(build_hardware_section())

        elif section == "network":
            lines.append("## 4. Network")
            lines.append("")
            lines.extend(build_network_section())

        elif section == "firewall":
            lines.append("## 5. Firewall and packet filters")
            lines.append("")
            lines.extend(build_firewall_section())

        elif section == "services":
            lines.append("## 6. Services")
            lines.append("")
            lines.extend(build_services_section())

        elif section == "docker":
            lines.append("## 7. Docker & containers")
            lines.append("")
            lines.extend(build_docker_section())

        elif section == "packages":
            lines.append("## 8. Packages")
            lines.append("")
            lines.extend(build_packages_section(pkg_file, pkg_mode))

        return title_suffix, lines

    if split_reports:
        for section in ordered:
            if section not in sections:
                continue
            title_suffix, lines = build_single_section_report(section)
            report_file = snapshot_dir / f"system-report-{hostname}-{section}-{timestamp}.md"
            report_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
            created.append(report_file)
    else:
        lines: List[str] = []
        lines.append(f"# System Report: {hostname}")
        lines.append("")
        lines.append(f"- Snapshot path: `{snapshot_dir}`")
        lines.append(f"- Captured at: `{timestamp}`")
        lines.append(f"- Distro ID: `{distro_id}`")
        lines.append(f"- Distro like: `{distro_like}`")
        lines.append("")

        for section in ordered:
            if section not in sections:
                continue

            if section == "meta":
                lines.append("## 1. Snapshot & meta")
                lines.append("")
                lines.append(fenced_text(meta_file))
                lines.append("")

            elif section == "os":
                lines.append("## 2. Operating system")
                lines.append("")
                lines.extend(build_os_section())
                lines.append("")

            elif section == "hardware":
                lines.append("## 3. Hardware and storage")
                lines.append("")
                lines.extend(build_hardware_section())
                lines.append("")

            elif section == "network":
                lines.append("## 4. Network")
                lines.append("")
                lines.extend(build_network_section())
                lines.append("")

            elif section == "firewall":
                lines.append("## 5. Firewall and packet filters")
                lines.append("")
                lines.extend(build_firewall_section())
                lines.append("")

            elif section == "services":
                lines.append("## 6. Services")
                lines.append("")
                lines.extend(build_services_section())
                lines.append("")

            elif section == "docker":
                lines.append("## 7. Docker & containers")
                lines.append("")
                lines.extend(build_docker_section())
                lines.append("")

            elif section == "packages":
                lines.append("## 8. Packages")
                lines.append("")
                lines.extend(build_packages_section(pkg_file, pkg_mode))
                lines.append("")

        report_file = snapshot_dir / f"system-report-{hostname}-{timestamp}.md"
        report_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        created.append(report_file)

    return created


# ---------------------------------------------------------------------------
# Anonymization
# ---------------------------------------------------------------------------

def anonymize_report(report_file: Path) -> None:
    """
    Apply basic anonymization:
      - Machine ID / Boot ID lines
      - IPv4 addresses
      - MAC addresses
    """
    text = report_file.read_text(encoding="utf-8", errors="ignore")

    text = re.sub(r"(Machine ID:).*", r"\1 [anonymized]", text)
    text = re.sub(r"(Boot ID:).*", r"\1 [anonymized]", text)

    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "10.0.0.x", text)

    text = re.sub(
        r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b",
        "02:00:00:00:00:01",
        text,
    )

    report_file.write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Collect system snapshot and optionally generate a Markdown report."
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        default="./reports",
        help="Directory to write snapshot & report (default: ./reports)",
    )
    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Do not generate Markdown report, only raw snapshot files",
    )
    parser.add_argument(
        "--packages",
        choices=["suppress", "minimal", "verbose"],
        default="minimal",
        help="Package mode: suppress|minimal|verbose (default: minimal)",
    )
    parser.add_argument(
        "--anonymize",
        action="store_true",
        help="Anonymize sensitive data in the Markdown report",
    )
    parser.add_argument(
        "--sections",
        default="all",
        help=(
            "Comma-separated sections to include in the report: "
            "meta,os,hardware,network,firewall,services,docker,packages,all "
            "(default: all)"
        ),
    )
    parser.add_argument(
        "--split-reports",
        action="store_true",
        help="Generate one Markdown report per section instead of a single combined report",
    )

    args = parser.parse_args()

    raw_sections = [s.strip().lower() for s in args.sections.split(",") if s.strip()]
    all_section_keys = [
        "meta",
        "os",
        "hardware",
        "network",
        "firewall",
        "services",
        "docker",
        "packages",
    ]

    if not raw_sections or "all" in raw_sections:
        selected_sections: Set[str] = set(all_section_keys)
    else:
        selected_sections = {s for s in raw_sections if s in all_section_keys}
        if not selected_sections:
            selected_sections = set(all_section_keys)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    hostname = platform.node() or run_cmd(["hostname"]) or "unknown-host"

    snapshot_dir = output_dir / f"system-info-{hostname}-{timestamp}"
    snapshot_dir.mkdir(parents=True, exist_ok=True)

    print(f"Snapshot directory: {snapshot_dir}")

    distro_id, distro_like = detect_distro()
    family = detect_family(distro_id, distro_like)

    # Paths to section files
    meta_file = snapshot_dir / "01-meta.txt"
    os_file = snapshot_dir / "02-os.txt"
    hw_file = snapshot_dir / "03-hardware.txt"
    net_file = snapshot_dir / "04-network.txt"
    fw_file = snapshot_dir / "05-firewall.txt"
    srv_file = snapshot_dir / "06-services.txt"
    docker_file = snapshot_dir / "07-docker.txt"
    pkg_file = snapshot_dir / "08-packages.txt"

    # Collect sections
    print("Collecting generic system info...")
    collect_meta(meta_file, snapshot_dir, hostname, timestamp, distro_id, distro_like)
    collect_os(os_file)
    collect_os_distro_specific(os_file, family, distro_id)
    collect_hw(hw_file)
    collect_net(net_file)
    collect_fw(fw_file)
    collect_services(srv_file)
    collect_docker(docker_file)

    print(f"Collecting package info (mode: {args.packages}) (family: {family})...")
    collect_packages(pkg_file, family, args.packages, snapshot_dir)

    if args.no_report:
        print("Skipping Markdown report (--no-report).")
        print(f"Snapshot dir: {snapshot_dir}")
        return

    print("Generating Markdown report(s)...")
    report_files = generate_markdown_reports(
        snapshot_dir,
        hostname,
        distro_id,
        distro_like,
        meta_file,
        os_file,
        hw_file,
        net_file,
        fw_file,
        srv_file,
        docker_file,
        pkg_file,
        args.packages,
        selected_sections,
        args.split_reports,
    )

    if args.anonymize:
        print("Applying basic anonymization to Markdown report(s)...")
        for rf in report_files:
            anonymize_report(rf)

    print("Done.")
    print(f"Snapshot dir: {snapshot_dir}")
    for rf in report_files:
        print(f"Report file:  {rf}")


if __name__ == "__main__":
    main()
