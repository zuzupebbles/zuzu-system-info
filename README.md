Here’s an updated README with added public-facing sections (Installation, Contributing, License, Author) while keeping your existing content intact.

````markdown
# `zuzu-system-info.py`

A Python script that collects a structured snapshot of a Linux host and generates an LLM-friendly Markdown report.

It combines the ideas from the original `qwi-system-info.sh` / `qwi-system-report.sh` pair into a single tool:  
**collect snapshot → optionally generate report right away**.

---

## 1. Goals and design

This script is built to:

- Capture **stable, textual snapshots** of Linux hosts that can be archived, versioned, and diffed.
- Produce **Markdown reports** that are:
  - readable for humans,
  - cheap for LLMs to ingest,
  - structured with predictable tables and headings.
- Keep secrets and host identifiers out of the high-level report where possible, while still keeping the raw snapshot around.

Generation pattern:

1. Run `zuzu-system-info.py` on the host.
2. It creates `system-info-HOSTNAME-YYYYMMDD-HHMMSS/` with text files.
3. It optionally creates one or more `system-report-*.md` files in that directory.
4. You can archive or feed the Markdown into an LLM.

---

## 2. Snapshot layout

Running the script (without options) creates a directory like:

```text
reports/
  system-info-HOSTNAME-20251122-120305/
    01-meta.txt
    02-os.txt
    03-hardware.txt
    04-network.txt
    05-firewall.txt
    06-services.txt
    07-docker.txt
    08-packages.txt
    system-report-HOSTNAME-20251122-120305.md   # default combined report
````

Each `0X-*.txt` file is a raw dump of commands:

* `01-meta.txt`
  Host metadata, timestamps, `date`, `uptime`, `who`.

* `02-os.txt`
  `uname`, `hostnamectl`, `/etc/os-release`, `lsb_release`, `ldd --version`.

* `03-hardware.txt`
  `lscpu`, `free -h`, `lsblk`, `df -h`.

* `04-network.txt`
  `ip -br addr`, `ip route`, `ip -6 route`, `/etc/resolv.conf`, **`ss -lntu` (new)**.

* `05-firewall.txt`
  `iptables -L -n -v`, `ip6tables -L -n -v`, `nft list ruleset`, `ufw status verbose`.

* `06-services.txt`
  `systemctl list-units --type=service`, `systemctl --failed`.

* `07-docker.txt`
  `docker info`, `docker ps`, `docker network ls` (with bridge iface guessing), `docker volume ls`, `docker images`.

* `08-packages.txt`
  Distro-family-specific package snapshots:

    * `dpkg-query -W` on Debian family
    * `pacman -Q` on Arch
    * `rpm -qa` on RHEL/SUSE
    * Optionally filtered to “core” packages depending on mode.

---

## 3. CLI usage

```bash
./zuzu-system-info.py \
  --output-dir ./reports \
  --packages minimal \
  --sections meta,os,hardware,network,firewall,services,docker,packages \
  --split-reports \
  --anonymize
```

### Options

* `-o, --output-dir DIR`
  Root directory for snapshots and reports (default `./reports`).

* `--no-report`
  Only collect raw `0X-*.txt` snapshot files; skip Markdown generation.

* `--packages {suppress|minimal|verbose}`

    * `suppress`: write a short “suppressed” note into `08-packages.txt`, and output the same in the report.
    * `minimal`: store only “core” packages (matching regexes from `core-packages-<family>.patterns` or `core-packages-generic.patterns`) plus a small explanatory header.
    * `verbose`: store full package manager output; the report points to the raw file instead of inlining everything.

* `--anonymize`
  Post-processes the generated Markdown reports:

    * masks IPv4 addresses as `10.0.0.x`,
    * masks MAC addresses,
    * redacts `Machine ID` and `Boot ID` lines.

* `--sections LIST`
  Comma-separated subset of:
  `meta,os,hardware,network,firewall,services,docker,packages,all`
  Defaults to `all`.

* `--split-reports`
  Instead of a single combined `system-report-HOST-timestamp.md`, generate one Markdown file per selected section.

---

## 4. Report structure

The default combined report has these top-level headings:

1. **Snapshot & meta** (`01-meta.txt`)
2. **Operating system**
3. **Hardware and storage**
4. **Network**
5. **Firewall and packet filters**
6. **Services**
7. **Docker & containers**
8. **Packages**

Each of the `build_*` functions is responsible for **only** the inner content and *sub-headings*, and all of them use the same `md_table()` helper for tables so the formatting stays consistent.

### 4.1 Meta section (1. Snapshot & meta)

* Embeds the full contents of `01-meta.txt` as a fenced `text` block.
* Gives LLMs an easy “anchor” for when the snapshot was taken and which host it refers to.

### 4.2 OS section (2. Operating system)

Uses `build_os_section()`:

* Summarizes OS with a table: `OS`, `Kernel`, `Arch`, `Distro ID`, `ID_LIKE`.
* Captures `Kernel and libc` (first line of `ldd --version`).
* Extracts non-identifying hardware details from `hostnamectl` (vendor, model, firmware).
* Embeds `/etc/os-release`, `lsb_release -a`, `arch-release` marker, and raw `uname -a` as fenced blocks.

### 4.3 Hardware section (3. Hardware and storage)

Uses `build_hardware_section()`:

* `3.1 CPU summary` from `lscpu`:

    * model, arch, sockets, cores, threads, virtualization flags, etc.

* `3.2 Memory` from `free -h`:

    * RAM (total/used/free/shared/buff-cache/available) and swap (if present).

* `3.3 Block devices` from `lsblk -P`:

    * physical disks with transport (SATA/SCSI/NVMe/iscsi), rotational flag, model;
    * logical children (partitions, LUKS, LVM) with parent mapping and mountpoints.

* `3.4 Filesystem usage` from `df -h`:

    * retains overlay entries so Docker layers are visible to an LLM.

### 4.4 Network section (4. Network)

Uses `build_network_section()`:

* `4.1 Interface summary` from `ip -br addr`:

    * interface, state, IPv4 list, IPv6 list.

* `4.2 IPv4 routing table` from `ip route`:

    * destination, gateway, dev, src, extra flags.

* `4.3 IPv6 routing table` from `ip -6 route`.

* `4.4 DNS configuration` from `/etc/resolv.conf`:

    * search domains, nameservers.

* **4.5 Listening sockets (new)**:

    * runs `ss -lntu` and embeds the output in a fenced block.
    * this gives a quick view of **which ports are listening** on which addresses without trying to parse every connection.

Note: the raw `04-network.txt` still exists for deeper analysis.

### 4.5 Firewall section (5. Firewall and packet filters)

Uses `build_firewall_section()`:

* Parses `iptables -L -n -v` and `ip6tables -L -n -v` into:

    * default policies (`INPUT`, `FORWARD`, `OUTPUT`),
    * a table of `FORWARD` rules for IPv4,
    * Docker-related chains (`DOCKER*`).

* Embeds raw `nft list ruleset` in a fenced `text` block if present.

* Embeds raw `ufw status verbose` in a fenced block if present.

All of this stays reasonably compact while still letting an LLM understand **policy shape**.

### 4.6 Services section (6. Services)

Uses `build_services_section()`:

* Runs `systemctl list-units --type=service` and `systemctl --failed`.
* Parses them into rows:

    * **6.1 Running services**: sub-state `running`.
    * **6.2 Exited services**: sub-state `exited` / `dead`.
    * **6.3 Failed services**: from both the main list and `systemctl --failed`, de-duplicated by unit name.

On non-systemd systems or when `systemctl` isn’t present, it emits explicit “skipping” notes.

### 4.7 Docker section (7. Docker & containers)

Uses `build_docker_section()`, which talks directly to Docker via structured JSON:

* **7.1 Docker engine**:

    * client/server version, API versions, Go version, OS/arch, runtime & driver info,
    * registry mirrors and insecure registries (if configured).

* **7.2 Containers**:

    * table of all containers from `docker ps --all`:

        * name, image, state, status, ports, networks.

* **7.3 Compose projects**:

    * uses `docker inspect` (per container) to extract `com.docker.compose.project` labels,
    * shows container ID (short), name, and compose project.

* **7.4 Docker networks**:

    * table of name, driver, scope, subnet, gateway,
    * subnet/gateway from `docker network inspect`.

* **7.5 Docker volumes**:

    * name, driver, scope, mountpoint (from `docker volume inspect`).

* **7.6 Docker images**:

    * repository, tag, ID, size, “created since”, “containers using”.

If Docker isn’t installed, sections gracefully report “not available”.

### 4.8 Packages section (8. Packages)

Uses `build_packages_section(pkg_file, pkg_mode)` and the snapshot from `collect_packages()`:

* Works for all supported families through a single text format.

* **Minimal mode**:

    * `collect_packages()` filters raw manager output using regex patterns loaded from:

        * `core-packages-<family>.patterns` or
        * `core-packages-generic.patterns`.

    * The report shows:

        * `8.1 Core OS / infrastructure packages`:

            * table: `Manager`, `Package`, `Version / details`.

* **Verbose mode**:

    * full package manager output is saved to `08-packages.txt`.
    * the report:

        * optionally includes `8.1` if any `# core packages` block exists,
        * always includes `8.2 Full package lists (verbose mode)` with a line count and a pointer to the raw file rather than inlining thousands of lines.

* **Suppress mode**:

    * snapshot file notes suppression,
    * report includes a single sentence explaining that packages were intentionally not collected.

---

## 5. Consistency improvements vs earlier Python version

Compared to the earlier, more ad-hoc Python port:

1. **Unified heading and section numbering**

    * Top-level headings and numbering are now managed only in `generate_markdown_reports()`.
    * All `build_*` functions return *inner* content and sub-headings (`### 2.1`, `### 3.1`, etc.) but **do not** inject their own `##` top-level headings anymore.
    * Prevents duplicate headings like `## OS details` followed by `## 2. Operating system`.

2. **Single Markdown table helper**

    * All sections now use a shared `md_table(headers, rows)` helper.
    * No more manual pipe-wrangling in individual sections; this keeps table syntax uniform and easy for downstream tooling (and LLMs).

3. **Packages section is fully wired up**

    * The previous script had a `build_packages_section()` that wasn’t called correctly (signature mismatch; no arguments being passed).
    * Now:

        * `build_packages_section(pkg_file, pkg_mode)` is called from both single-section and combined report paths.
        * It parses the existing `08-packages.txt` format used by `collect_packages()`.
        * Handles all modes (`suppress`, `minimal`, `verbose`) and emits clear text when there’s no core subset.

4. **More robust package snapshot parsing**

    * Ignores the “Detected family” banner as if it were a package manager.
    * Recognizes `# core packages (pattern-based)` blocks from any manager (`dpkg-query`, `pacman`, `rpm`).
    * Deduces the manager from headers like `== dpkg-query -W ==`, `== pacman -Q ==`, `== rpm -qa ==`.

5. **Shared `safe_cmd()` helper**

    * Many sections previously defined their own local `_safe_cmd` wrappers.
    * Now a global `safe_cmd()` normalizes “command not available” noise and keeps the build functions shorter and more consistent.

6. **Section ordering and naming**

    * `generate_markdown_reports()` now uses a canonical order:
      `meta → os → hardware → network → firewall → services → docker → packages`.
    * The same numbering is used in both combined and split-report modes.

---

## 6. New information added for LLMs

Two notable additions that weren’t present in the original Python version:

1. **Listening sockets snapshot (`ss -lntu`)**

    * **Snapshot side**:
      `collect_net()` now appends a `== ss -lntu ==` section to `04-network.txt`.

    * **Report side**:

        * `build_network_section()` has a new subsection `4.5 Listening sockets (ss -lntu)`.
        * The raw `ss -lntu` output is embedded in a fenced `text` block.

    * Why this helps LLMs:

        * It makes the **exposed surface area** of the host explicit (what ports are listening and on which addresses).
        * It’s compact enough to keep, and an LLM can parse it easily into “services on ports” without you having to pre-interpret everything.

2. **Clearer package handling in reports**

    * The packages section now:

        * explicitly states the package mode,
        * renders a clean “core packages” table rather than dumping raw text,
        * avoids inlining huge lists in verbose mode but still quantifies their size.

    * This is particularly helpful if you’re asking an LLM things like:

        * “Compare base OS packages across these hosts.”
        * “Which kube/container-runtime bits are installed?”

---

## 7. Anonymization model

The anonymizer is intentionally simple but effective for sharing reports with an LLM:

* Rewrites:

    * `Machine ID: ...` → `Machine ID: [anonymized]`
    * `Boot ID: ...`     → `Boot ID: [anonymized]`

* Replaces any IPv4 address with `10.0.0.x`.

* Replaces any MAC address with `02:00:00:00:00:01`.

This means:

* The logical structure (which interface talks to which subnet, which ports are open) remains visible.
* Concrete addresses are hidden so you can safely ship the report to a model or another human.

---

## 8. Typical workflow

1. On the host:

   ```bash
   ./zuzu-system-info.py --output-dir /srv/reports --packages minimal
   ```

2. Archive the snapshot:

   ```bash
   tar czf system-info-$(hostname)-$(date +%F).tar.gz /srv/reports/system-info-*
   ```

3. On your analysis machine, collect multiple hosts’ `system-report-*.md` and feed them into an LLM for:

    * architecture mapping,
    * migration planning,
    * sanity-checking network or Docker layouts,
    * spotting weird firewall behaviors.

You get raw data for auditors and a clean, normalized Markdown interface for your future robot collaborators.

---

## 9. Installation

### 9.1 Requirements

* Python 3.8+ (tested with modern CPython).
* Standard Linux userland with:

    * `ip`, `ss` (usually from `iproute2`),
    * `iptables` / `ip6tables` and/or `nft`,
    * `systemctl` (for systemd-based systems),
    * Docker CLI (`docker`) if you want container sections,
    * a supported package manager:

        * `dpkg-query` (Debian / Ubuntu, etc.),
        * `pacman` (Arch / derivatives),
        * `rpm` (RHEL / SUSE / Fedora family).

The script degrades gracefully when some tools are missing and will note skipped sections.

### 9.2 Manual install

Clone the repository and install the script somewhere on your `$PATH`:

```bash
git clone https://github.com/zuzupebbles/zuzu-system-info.git
cd zuzu-system-info

# Option 1: run in-place
python3 ./zuzu-system-info.py --help

# Option 2: install as a convenience wrapper
sudo install -m 0755 zuzu-system-info.py /usr/local/sbin/zuzu-system-info
```

If you packaged this via a distro-specific mechanism (e.g. an Arch PKGBUILD), it should install a `zuzu-system-info` executable into something like `/usr/local/sbin` or `/usr/bin` and pull in any runtime dependencies as needed.

---

## 10. Contributing

Contributions are welcome, especially around:

* additional distro/package-manager support,
* smarter anonymization strategies,
* extra sections or more robust parsing of existing ones,
* packaging for popular distributions.

Basic guidelines:

* Keep the Markdown output predictable and LLM-friendly:

    * stable headings,
    * consistent tables via the shared `md_table()` helper,
    * avoid inlining enormous raw dumps in the report.
* Avoid leaking sensitive identifiers into the high-level report; prefer leaving them in the raw snapshot files.
* Try to keep each section’s logic self-contained and well-documented.

Bug reports and pull requests are preferred over telepathic suggestions.

---

## 11. License

This project is licensed under the **MIT License**.

See the `LICENSE` file in this repository for the full text.

---

## 12. Author & acknowledgements

**Author / Maintainer**

* **Name:** Peter Knauer (zuzu@quantweave.ca)

**Acknowledgements**

* Inspired by the original shell scripts `qwi-system-info.sh` and `qwi-system-report.sh`.
* Thanks to everyone who tests this on weird Linux setups, container-heavy hosts, and lab boxes and reports back what breaks.

By design, this script exists to make life easier for humans and LLMs trying to understand real-world Linux systems from clean, structured snapshots.

```
```
