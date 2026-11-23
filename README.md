<p align="center">
  <img src="edr_icon.png" alt="Orlitum EDR Logo" width="120" />
</p>

<h1 align="center">Orlitum EDR (Community Edition)</h1>

<p align="center">
  Autonomous cross-distribution Linux EDR &amp; HIPS agent built in pure Python.<br/>
  Explores host-level threat detection, YARA/Sigma scanning, HMAC-FIM, and anti-tamper mechanisms.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-2ea44f?style=flat-square&logo=linux&logoColor=white" alt="Platform Linux" />
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776ab?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+" />
  <img src="https://img.shields.io/badge/Detection-YARA%20%2B%20Sigma-d9534f?style=flat-square" alt="YARA + Sigma" />
  <img src="https://img.shields.io/github/license/orlitum/orlitum-edr?style=flat-square" alt="License" />
</p>

---

## Key Capabilities

* **Multi-Engine Threat Detection:** Static signature scanning via **YARA** (`rules/*.yar`) combined with behavioral Indicator of Attack (IOA) rules in **Sigma** format (`rules/sigma/linux_ioa.yml`).
* **Real-Time File Integrity Monitoring (HMAC-FIM):** Cryptographically signed baseline verification and live filesystem watching via `inotify` / `watchdog`.
* **Persistence & Behavioral Auditing:** Automated checks across 10+ Linux persistence vectors (`systemd`, `cron`, `LD_PRELOAD`, SSH keys, shell profiles, kernel modules) and live `/proc` process-tree inspection.
* **Lightweight Namespace Sandbox:** Built-in process isolation wrapper (`orlitum_sandbox.py`) utilizing Linux `unshare` namespaces for safe detonation and inspection.
* **Cross-Distribution & Standalone Ready:** Supports Fedora/RHEL, Ubuntu/Debian, Arch Linux, and openSUSE out of the box, with graceful fallback on non-systemd environments and containers.

---

## Quick Start

~~~bash
git clone https://github.com/orlitum/orlitum-edr.git
cd orlitum-edr
chmod +x install.sh
./install.sh
~~~

Launch the interactive CLI control panel:

~~~bash
./orlitum_menu.sh
~~~

Or run individual modules directly:

~~~bash
python3 orlitum.py --self-test        # Run built-in integrity & detection self-tests
python3 orlitum.py --audit-persist    # Audit 10+ Linux persistence vectors
python3 orlitum.py --audit-behavior   # Inspect active processes for behavioral anomalies
python3 orlitum.py --scan /tmp        # Scan a target directory with YARA rules
~~~

---

## Repository Structure

| Path | Description |
| :--- | :--- |
| `orlitum.py` | Core EDR engine (YARA/Sigma detection, FIM, behavioral & persistence auditing) |
| `orlitum_sandbox.py` | Linux namespace isolation sandbox (`unshare`) |
| `orlitum_menu.sh` | Interactive terminal control panel |
| `orlitum_tuning.json` | Configurable thresholds, exclusions, and tuning parameters |
| `install.sh` | Cross-distro dependency installer & `systemd` unit setup |
| `rules/` | YARA signatures and Linux IOA Sigma rules |

---

## Disclaimer

This project is developed as an independent cybersecurity research and learning initiative. Test thoroughly in staging or isolated environments before deploying on production hosts.
