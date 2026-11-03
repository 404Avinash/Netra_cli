#!/usr/bin/env python3
"""
NETRA_CLI: Network & Endpoint Threat and Resilience Assessor CLI.

A lightweight, zero-dependency security assessment utility that inspects a website's
externally visible security posture, establishes a reviewed baseline, detects
security drift/regressions, and dispatches issue alerts via Swytchcode's execution authority.
"""

import argparse
import datetime
import http.client
import json
import os
import re
import socket
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

VERSION = "1.0.0"

# ANSI Color Utilities
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_GREEN = "\033[32m"
ANSI_RED = "\033[31m"
ANSI_YELLOW = "\033[33m"
ANSI_BLUE = "\033[34m"
ANSI_MAGENTA = "\033[35m"
ANSI_CYAN = "\033[36m"


def should_use_color() -> bool:
    """Determine whether color output should be enabled."""
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def color_text(text: str, color_code: str) -> str:
    """Wrap text in ANSI color codes if terminal supports color."""
    if should_use_color():
        return f"{color_code}{text}{ANSI_RESET}"
    return text


def status_badge(status: str) -> str:
    """Format status string with appropriate color badge."""
    upper = status.upper()
    if upper in ("PASS", "PRESENT"):
        return color_text(f"[{upper}]", ANSI_GREEN + ANSI_BOLD)
    elif upper in ("FAIL", "MISSING", "EXPIRED"):
        return color_text(f"[{upper}]", ANSI_RED + ANSI_BOLD)
    elif upper in ("INCONCLUSIVE", "WARNING"):
        return color_text(f"[{upper}]", ANSI_YELLOW + ANSI_BOLD)
    return f"[{upper}]"


def severity_badge(severity: str) -> str:
    """Format severity level with appropriate color badge."""
    upper = severity.upper()
    if upper == "HIGH":
        return color_text(upper, ANSI_RED + ANSI_BOLD)
    elif upper == "MEDIUM":
        return color_text(upper, ANSI_YELLOW + ANSI_BOLD)
    elif upper == "LOW":
        return color_text(upper, ANSI_BLUE)
    return upper


def strip_ansi(text: str) -> str:
    """Remove ANSI escape sequences from string for accurate length calculation."""
    return re.sub(r"\033\[[0-9;]*m", "", text)


def pad_ansi(text: str, width: int, align: str = "left") -> str:
    """Pad string to visual width accounting for non-printable ANSI escape sequences."""
    visible_len = len(strip_ansi(text))
    padding = max(0, width - visible_len)
    if align == "right":
        return (" " * padding) + text
    return text + (" " * padding)


BANNER = r"""
  _   _ _____ _____ ____      _       ____ _     ___ 
 | \ | | ____|_   _|  _ \    / \     / ___| |   |_ _|
 |  \| |  _|   | | | |_) |  / _ \   | |   | |    | | 
 | |\  | |___  | | |  _ <  / ___ \  | |___| |___ | | 
 |_| \_|_____| |_| |_| \_\/_/   \_\  \____|_____|___|
      Network & Endpoint Threat & Resilience Assessor
"""

KNOWN_PORT_SERVICES = {
    21: ("FTP Server", "HIGH"),
    22: ("SSH Service", "LOW"),
    23: ("Telnet Daemon", "HIGH"),
    25: ("SMTP Mail", "LOW"),
    53: ("DNS Resolver", "INFO"),
    80: ("HTTP Web", "LOW"),
    443: ("HTTPS Web", "INFO"),
    631: ("CUPS Print", "INFO"),
    1314: ("Local Service", "INFO"),
    1337: ("Suspicious Elite / Backdoor", "CRITICAL"),
    2375: ("Docker Unencrypted Daemon", "HIGH"),
    2376: ("Docker TLS Daemon", "MEDIUM"),
    3000: ("Dev Server (Node/React/Rails)", "MEDIUM"),
    3306: ("MySQL Database", "HIGH"),
    3333: ("Cryptominer Stratum Port", "CRITICAL"),
    4000: ("Dev Server", "MEDIUM"),
    4444: ("Metasploit / C2 Listener", "CRITICAL"),
    5000: ("Dev Server (Flask/ASP.NET)", "MEDIUM"),
    5173: ("Vite Dev Server", "MEDIUM"),
    5432: ("PostgreSQL Database", "HIGH"),
    5555: ("Cryptominer Port", "CRITICAL"),
    5678: ("Debugger / Service", "HIGH"),
    6379: ("Redis Database", "HIGH"),
    6667: ("IRC Botnet Port", "CRITICAL"),
    8000: ("Dev Server (Python/Django)", "MEDIUM"),
    8080: ("Dev Server / Web Proxy", "MEDIUM"),
    8443: ("HTTPS Dev Server", "LOW"),
    8888: ("Jupyter Notebook", "MEDIUM"),
    9200: ("Elasticsearch Database", "HIGH"),
    9229: ("Node.js Debugger", "HIGH"),
    11434: ("Ollama AI Server", "INFO"),
    27017: ("MongoDB Database", "HIGH"),
}

SUSPICIOUS_PORTS = {4444, 1337, 3333, 5555, 6667, 31337, 666, 23, 445}


def is_local_target(target: str | None) -> bool:
    """Determine whether a target refers to the local host/laptop."""
    if not target:
        return True
    clean = target.strip().lower()
    if clean in ("localhost", "127.0.0.1", "::1", "host", "local", "0.0.0.0"):
        return True
    return False


def get_primary_ip() -> str:
    """Determine primary local network IPv4 address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def format_bytes(num_bytes: int | float) -> str:
    """Format byte counts into human-readable strings (e.g. 3.69 GB, 250 KB)."""
    b = float(num_bytes)
    if b >= 1024 ** 3:
        return f"{b / (1024 ** 3):.2f} GB"
    elif b >= 1024 ** 2:
        return f"{b / (1024 ** 2):.1f} MB"
    elif b >= 1024:
        return f"{b / 1024:.1f} KB"
    return f"{int(b)} B"


def format_rate(bytes_sec: float) -> str:
    """Format transfer rates into KB/s or MB/s."""
    b = float(bytes_sec)
    if b >= 1024 ** 2:
        return f"{b / (1024 ** 2):.1f} MB/s"
    elif b >= 1024:
        return f"{b / 1024:.1f} KB/s"
    return f"{b:.0f} B/s"


def split_addr_port(addr_port: str) -> tuple[str, int]:
    """Split socket string into address and port."""
    clean = addr_port.strip()
    idx = clean.rfind(":")
    if idx == -1:
        return clean, 0
    addr_part = clean[:idx]
    if "%" in addr_part:
        addr_part = addr_part.split("%")[0]
    addr = addr_part.strip("[]")
    port_str = clean[idx + 1 :]
    try:
        port = int(port_str)
    except ValueError:
        port = 0
    return addr, port


def categorize_exposure(bind_addr: str) -> str:
    """Categorize a bind address as EXPOSED (all interfaces/LAN) or LOCAL (loopback)."""
    clean = bind_addr.strip("[]").lower()
    if clean in ("0.0.0.0", "*", "::", "::0"):
        return "EXPOSED"
    if clean.startswith("127.") or clean in ("::1", "localhost"):
        return "LOCAL"
    return "EXPOSED"


def identify_connection_service(remote_ip: str, remote_port: int) -> str:
    """Identify destination service or provider from remote IP and port."""
    if remote_ip.startswith("127.") or remote_ip in ("::1", "localhost"):
        return "Local Loopback (IPC)"
    if (
        remote_ip.startswith("192.168.")
        or remote_ip.startswith("10.")
        or remote_ip.startswith("172.16.")
        or remote_ip.startswith("172.17.")
        or remote_ip.startswith("172.18.")
        or remote_ip.startswith("172.19.")
    ):
        return "Local Network (LAN)"

    if remote_port == 443:
        if remote_ip.startswith("140.82."):
            return "GitHub (TLS)"
        if remote_ip.startswith("34.") or remote_ip.startswith("35.") or remote_ip.startswith("142.250.") or remote_ip.startswith("172.217."):
            return "Google Cloud (TLS)"
        if remote_ip.startswith("104.") or remote_ip.startswith("172.67."):
            return "Cloudflare (TLS)"
        if remote_ip.startswith("3.") or remote_ip.startswith("52.") or remote_ip.startswith("54."):
            return "AWS (TLS)"
        return "Encrypted HTTPS"
    elif remote_port == 80:
        return "Unencrypted HTTP (Plaintext)"
    elif remote_port == 21:
        return "Unencrypted FTP (Plaintext)"
    elif remote_port == 23:
        return "Unencrypted Telnet (Plaintext)"
    elif remote_port in SUSPICIOUS_PORTS:
        return f"Suspicious Port {remote_port}"
    return f"External Port {remote_port}"


def read_proc_net_dev(proc_path: str = "/proc/net/dev") -> dict[str, dict]:
    """Parse /proc/net/dev into interface traffic dictionaries."""
    interfaces = {}
    if not os.path.exists(proc_path):
        return interfaces

    try:
        with open(proc_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception:
        return interfaces

    for line in lines[2:]:
        line_s = line.strip()
        if not line_s or ":" not in line_s:
            continue
        iface, rest = line_s.split(":", 1)
        iface = iface.strip()
        tokens = rest.split()
        if len(tokens) < 16:
            continue

        try:
            rx_bytes = int(tokens[0])
            rx_packets = int(tokens[1])
            rx_errs = int(tokens[2])
            rx_drop = int(tokens[3])
            tx_bytes = int(tokens[8])
            tx_packets = int(tokens[9])
            tx_errs = int(tokens[10])
            tx_drop = int(tokens[11])

            interfaces[iface] = {
                "rx_bytes": rx_bytes,
                "rx_packets": rx_packets,
                "rx_errs": rx_errs,
                "rx_drop": rx_drop,
                "tx_bytes": tx_bytes,
                "tx_packets": tx_packets,
                "tx_errs": tx_errs,
                "tx_drop": tx_drop,
            }
        except (ValueError, IndexError):
            continue

    return interfaces


def sample_interface_bandwidth(
    duration: float = 0.15, proc_path: str = "/proc/net/dev"
) -> dict:
    """Sample /proc/net/dev over brief interval to calculate rates and totals."""
    s1 = read_proc_net_dev(proc_path)
    t1 = time.time()
    if duration > 0:
        time.sleep(duration)
    s2 = read_proc_net_dev(proc_path)
    t2 = time.time()
    dt = max(t2 - t1, 0.001)

    result = {
        "primary_interface": "lo",
        "rx_bytes": 0,
        "tx_bytes": 0,
        "rx_rate_bps": 0.0,
        "tx_rate_bps": 0.0,
        "interfaces": {},
    }

    if not s2:
        return result

    best_iface = None
    best_traffic = -1

    for iface, data2 in s2.items():
        data1 = s1.get(iface, data2)
        rx_diff = max(0, data2["rx_bytes"] - data1["rx_bytes"])
        tx_diff = max(0, data2["tx_bytes"] - data1["tx_bytes"])
        rx_rate = rx_diff / dt
        tx_rate = tx_diff / dt

        result["interfaces"][iface] = {
            "rx_bytes": data2["rx_bytes"],
            "tx_bytes": data2["tx_bytes"],
            "rx_rate_bps": rx_rate,
            "tx_rate_bps": tx_rate,
            "rx_drop": data2["rx_drop"],
            "tx_drop": data2["tx_drop"],
            "rx_errs": data2["rx_errs"],
            "tx_errs": data2["tx_errs"],
        }

        if iface != "lo":
            tot = data2["rx_bytes"] + data2["tx_bytes"]
            if tot > best_traffic:
                best_traffic = tot
                best_iface = iface

    if not best_iface:
        best_iface = "lo" if "lo" in s2 else (list(s2.keys())[0] if s2 else "lo")

    result["primary_interface"] = best_iface
    if best_iface in result["interfaces"]:
        p_data = result["interfaces"][best_iface]
        result["rx_bytes"] = p_data["rx_bytes"]
        result["tx_bytes"] = p_data["tx_bytes"]
        result["rx_rate_bps"] = p_data["rx_rate_bps"]
        result["tx_rate_bps"] = p_data["tx_rate_bps"]

    return result


def parse_ss_sockets(ss_output: str) -> tuple[list[dict], list[dict], list[dict]]:
    """Parse 'ss -tunap' output into listening_ports, established_conns, other_conns."""
    listening_ports = []
    established_conns = []
    other_conns = []
    seen_listeners = set()

    for line in ss_output.splitlines():
        line_s = line.strip()
        if not line_s or line_s.startswith("Netid") or line_s.startswith("State"):
            continue

        parts = line_s.split()
        if len(parts) < 6:
            continue

        proto = parts[0].lower()
        state = parts[1].upper()
        local_ap = parts[4]
        peer_ap = parts[5]

        proc_matches = re.findall(r'\("([^"]+)",pid=(\d+)', line_s)
        processes = [{"name": name, "pid": int(pid)} for name, pid in proc_matches]

        local_addr, local_port = split_addr_port(local_ap)
        remote_addr, remote_port = split_addr_port(peer_ap)

        is_tcp_listen = (proto == "tcp" and state == "LISTEN")
        is_udp_listen = (
            proto == "udp"
            and state == "UNCONN"
            and (remote_port == 0 or peer_ap.endswith(":*"))
            and (local_port < 1024 or local_port in KNOWN_PORT_SERVICES or local_port in SUSPICIOUS_PORTS or local_port == 5353)
        )
        if is_tcp_listen or is_udp_listen:
            if local_port <= 0:
                continue
            exposure = categorize_exposure(local_addr)
            service_name, default_sev = KNOWN_PORT_SERVICES.get(local_port, ("Service", "INFO"))

            if exposure == "EXPOSED":
                if local_port in (6379, 5432, 3306, 27017, 2375, 5678, 9229, 4444, 1337, 3333):
                    severity = "CRITICAL" if local_port in (4444, 1337, 3333) else "HIGH"
                elif local_port in (3000, 4000, 5000, 5173, 8080, 8888, 8000):
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            else:
                severity = "INFO"

            key = (proto, local_port, exposure)
            if key not in seen_listeners:
                seen_listeners.add(key)
                listening_ports.append({
                    "proto": proto,
                    "port": local_port,
                    "bind_address": local_addr,
                    "exposure": exposure,
                    "service": service_name,
                    "severity": severity,
                    "processes": processes,
                })
            else:
                for existing in listening_ports:
                    if (
                        existing["proto"] == proto
                        and existing["port"] == local_port
                        and existing["exposure"] == exposure
                    ):
                        existing_pids = {p["pid"] for p in existing["processes"]}
                        for pr in processes:
                            if pr["pid"] not in existing_pids:
                                existing["processes"].append(pr)
                                existing_pids.add(pr["pid"])

        elif state == "ESTAB":
            service_desc = identify_connection_service(remote_addr, remote_port)
            established_conns.append({
                "proto": proto,
                "local_address": local_ap,
                "local_port": local_port,
                "remote_address": peer_ap,
                "remote_ip": remote_addr,
                "remote_port": remote_port,
                "status": "ESTAB",
                "processes": processes,
                "service": service_desc,
            })
        else:
            other_conns.append({
                "proto": proto,
                "state": state,
                "local_address": local_ap,
                "remote_address": peer_ap,
                "processes": processes,
            })

    listening_ports.sort(key=lambda x: (0 if x["exposure"] == "EXPOSED" else 1, x["port"]))
    return listening_ports, established_conns, other_conns


def parse_proc_net_sockets() -> tuple[list[dict], list[dict], list[dict]]:
    """Pure Python fallback for Linux inspecting /proc/net/tcp, tcp6, udp, udp6."""
    listening_ports = []
    established_conns = []
    other_conns = []
    seen = set()

    def hex_to_ipv4(h: str) -> str:
        try:
            b = bytes.fromhex(h)
            return f"{b[3]}.{b[2]}.{b[1]}.{b[0]}"
        except Exception:
            return h

    files = [
        ("/proc/net/tcp", "tcp"),
        ("/proc/net/tcp6", "tcp"),
        ("/proc/net/udp", "udp"),
        ("/proc/net/udp6", "udp"),
    ]

    for path, proto in files:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception:
            continue

        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) < 10:
                continue
            local_raw = parts[1]
            rem_raw = parts[2]
            st_raw = parts[3]

            if ":" not in local_raw:
                continue
            loc_ip_h, loc_port_h = local_raw.split(":", 1)
            rem_ip_h, rem_port_h = rem_raw.split(":", 1)

            try:
                loc_port = int(loc_port_h, 16)
                rem_port = int(rem_port_h, 16)
            except ValueError:
                continue

            if len(loc_ip_h) == 8:
                loc_ip = hex_to_ipv4(loc_ip_h)
            elif loc_ip_h == "00000000000000000000000000000000":
                loc_ip = "::"
            elif loc_ip_h == "00000000000000000000000001000000":
                loc_ip = "::1"
            else:
                loc_ip = "::"

            if len(rem_ip_h) == 8:
                rem_ip = hex_to_ipv4(rem_ip_h)
            else:
                rem_ip = "0.0.0.0" if rem_ip_h == "00000000000000000000000000000000" else "::"

            is_tcp_listen = (proto == "tcp" and st_raw == "0A")
            is_udp_listen = (
                proto == "udp"
                and st_raw == "07"
                and (loc_port < 1024 or loc_port in KNOWN_PORT_SERVICES or loc_port in SUSPICIOUS_PORTS or loc_port == 5353)
            )
            if is_tcp_listen or is_udp_listen:
                if loc_port <= 0:
                    continue
                exposure = categorize_exposure(loc_ip)
                svc, def_sev = KNOWN_PORT_SERVICES.get(loc_port, ("Service", "INFO"))
                if exposure == "EXPOSED":
                    if loc_port in (6379, 5432, 3306, 27017, 2375, 5678, 9229, 4444, 1337, 3333):
                        sev = "CRITICAL" if loc_port in (4444, 1337, 3333) else "HIGH"
                    elif loc_port in (3000, 4000, 5000, 5173, 8080, 8888, 8000):
                        sev = "MEDIUM"
                    else:
                        sev = "LOW"
                else:
                    sev = "INFO"

                key = (proto, loc_port, exposure)
                if key not in seen:
                    seen.add(key)
                    listening_ports.append({
                        "proto": proto,
                        "port": loc_port,
                        "bind_address": loc_ip,
                        "exposure": exposure,
                        "service": svc,
                        "severity": sev,
                        "processes": [],
                    })
            elif st_raw == "01":
                svc = identify_connection_service(rem_ip, rem_port)
                established_conns.append({
                    "proto": proto,
                    "local_address": f"{loc_ip}:{loc_port}",
                    "local_port": loc_port,
                    "remote_address": f"{rem_ip}:{rem_port}",
                    "remote_ip": rem_ip,
                    "remote_port": rem_port,
                    "status": "ESTAB",
                    "processes": [],
                    "service": svc,
                })

    listening_ports.sort(key=lambda x: (0 if x["exposure"] == "EXPOSED" else 1, x["port"]))
    return listening_ports, established_conns, other_conns


def inspect_sockets() -> tuple[list[dict], list[dict], list[dict]]:
    """Try ss -tunap first; fall back to /proc/net."""
    try:
        proc = subprocess.run(
            ["ss", "-tunap"],
            capture_output=True,
            text=True,
            timeout=2.0,
        )
        if proc.returncode == 0 and proc.stdout:
            return parse_ss_sockets(proc.stdout)
    except Exception:
        pass
    return parse_proc_net_sockets()


def inspect_ssh_key_hygiene(ssh_dir: Path | None = None) -> dict:
    """Inspect ~/.ssh private key permissions (flag if wider than 0600)."""
    if ssh_dir is None:
        ssh_dir = Path.home() / ".ssh"

    if not ssh_dir.exists() or not ssh_dir.is_dir():
        return {
            "status": "PASS",
            "details": "No SSH directory found",
            "issues": [],
        }

    issues = []
    for f in ssh_dir.glob("id_*"):
        if f.is_file() and not f.name.endswith(".pub"):
            try:
                st = f.stat()
                mode = st.st_mode & 0o777
                if (mode & 0o077) != 0:
                    issues.append(
                        f"Private key '{f.name}' has unsafe permissions {oct(mode)[2:]} (should be 0600)"
                    )
            except Exception:
                pass

    if issues:
        return {
            "status": "FAIL",
            "details": "; ".join(issues),
            "issues": issues,
        }
    return {
        "status": "PASS",
        "details": "SSH keys have secure 0600 permissions",
        "issues": [],
    }


def inspect_workspace_secrets_hygiene(workspace_dir: Path | None = None) -> dict:
    """Inspect current workspace for unignored or world-readable secret .env files."""
    if workspace_dir is None:
        workspace_dir = Path.cwd()

    issues = []
    env_files = []
    for pattern in (".env", ".env.*"):
        for f in workspace_dir.glob(pattern):
            if f.is_file() and not f.name.endswith((".example", ".sample", ".template", ".md", ".txt")):
                env_files.append(f)

    for ef in env_files:
        try:
            res_tracked = subprocess.run(
                ["git", "ls-files", "--error-unmatch", ef.name],
                cwd=str(workspace_dir),
                capture_output=True,
                text=True,
            )
            if res_tracked.returncode == 0:
                issues.append(f"Secret file '{ef.name}' is actively TRACKED in git repository!")
                continue
        except Exception:
            pass

        try:
            res_ignored = subprocess.run(
                ["git", "check-ignore", ef.name],
                cwd=str(workspace_dir),
                capture_output=True,
                text=True,
            )
            if res_ignored.returncode != 0:
                issues.append(f"Secret file '{ef.name}' is NOT ignored in .gitignore")
        except Exception:
            pass

        try:
            st = ef.stat()
            if (st.st_mode & stat.S_IROTH) or (st.st_mode & stat.S_IWOTH):
                issues.append(
                    f"Secret file '{ef.name}' has unsafe world permissions ({oct(st.st_mode & 0o777)[2:]})"
                )
        except Exception:
            pass

    if issues:
        return {
            "status": "FAIL",
            "details": "; ".join(issues),
            "issues": issues,
        }
    return {
        "status": "PASS",
        "details": "No untracked or world-readable .env secrets found",
        "issues": [],
    }


def evaluate_threat_heuristics(
    listening_ports: list[dict],
    estab_conns: list[dict],
    other_conns: list[dict],
) -> list[dict]:
    """Detect suspicious ports, unencrypted traffic, and connection flood indicators."""
    threats = []

    for lp in listening_ports:
        port = lp.get("port", 0)
        if port in SUSPICIOUS_PORTS:
            threats.append({
                "category": f"Suspicious Listener :{port}",
                "severity": "CRITICAL",
                "port": port,
                "details": f"Port {port} active on {lp.get('bind_address')} ({lp.get('service')})",
                "recommendation": f"Terminate process on port {port} and verify binary integrity.",
            })

    remote_ip_counts = {}
    for c in estab_conns:
        r_port = c.get("remote_port", 0)
        r_ip = c.get("remote_ip", "")
        procs = c.get("processes", [])
        proc_name = procs[0]["name"] if procs else "unknown"

        if r_port in SUSPICIOUS_PORTS:
            threats.append({
                "category": f"Suspicious Connection :{r_port}",
                "severity": "CRITICAL",
                "port": r_port,
                "details": f"Active connection to {r_ip}:{r_port} by {proc_name} (known backdoor/miner port)",
                "recommendation": f"Kill process {proc_name} and check host network traffic logs.",
            })

        if r_port in (80, 21, 23) and not (r_ip.startswith("127.") or r_ip in ("::1", "localhost")):
            threats.append({
                "category": "Plaintext Outbound Traffic",
                "severity": "MEDIUM",
                "port": r_port,
                "details": f"Unencrypted outbound traffic to {r_ip}:{r_port} by {proc_name}",
                "recommendation": "Enforce TLS/HTTPS for external communications.",
            })

        if r_ip and not (r_ip.startswith("127.") or r_ip in ("::1", "localhost")):
            remote_ip_counts[r_ip] = remote_ip_counts.get(r_ip, 0) + 1

    for rip, cnt in remote_ip_counts.items():
        if cnt >= 20:
            threats.append({
                "category": "Connection Concentration",
                "severity": "MEDIUM",
                "details": f"{cnt} active connections to external IP {rip}",
                "recommendation": "Verify whether connection spike is legitimate application traffic.",
            })

    syn_recv_cnt = sum(
        1 for c in other_conns if c.get("state") in ("SYN-RECV", "SYN_RECV")
    )
    if syn_recv_cnt >= 10:
        threats.append({
            "category": "Possible Inbound SYN Flood",
            "severity": "HIGH",
            "details": f"{syn_recv_cnt} sockets in SYN_RECV state",
            "recommendation": "Enable TCP syncookies and review firewall rate limits.",
        })

    syn_sent_cnt = sum(
        1 for c in other_conns if c.get("state") in ("SYN-SENT", "SYN_SENT")
    )
    if syn_sent_cnt >= 15:
        threats.append({
            "category": "High SYN_SENT Spike",
            "severity": "MEDIUM",
            "details": f"{syn_sent_cnt} sockets in SYN_SENT state (possible rapid scan)",
            "recommendation": "Inspect outgoing processes initiating rapid connection attempts.",
        })

    return threats


def inspect_local_host(
    sample_duration: float = 0.15, proc_net_dev_path: str = "/proc/net/dev"
) -> dict:
    """Perform comprehensive local host security, network, and hygiene audit."""
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    hostname = socket.gethostname()
    primary_ip = get_primary_ip()

    net_telemetry = sample_interface_bandwidth(duration=sample_duration, proc_path=proc_net_dev_path)
    listening_ports, estab_conns, other_conns = inspect_sockets()
    threats = evaluate_threat_heuristics(listening_ports, estab_conns, other_conns)
    hygiene = {
        "ssh_keys": inspect_ssh_key_hygiene(),
        "workspace_secrets": inspect_workspace_secrets_hygiene(),
    }

    obs = {
        "target": "localhost",
        "type": "host",
        "hostname": hostname,
        "ip": primary_ip,
        "timestamp": now_iso,
        "network": net_telemetry,
        "listening_ports": listening_ports,
        "established_connections": estab_conns,
        "threats": threats,
        "hygiene": hygiene,
    }

    score, grade, bar = calculate_host_security_score(obs)
    obs["score"] = score
    obs["grade"] = grade
    obs["score_bar"] = bar

    return obs


def calculate_host_security_score(host_obs: dict) -> tuple[int, str, str]:
    """Calculate an objective 0-100 host security score, letter grade, and progress bar."""
    score = 100

    exposed_db_debugger = 0
    exposed_dev_servers = 0
    exposed_other = 0

    for p in host_obs.get("listening_ports", []):
        if p.get("exposure") == "EXPOSED":
            port = p.get("port", 0)
            if port in (6379, 5432, 3306, 27017, 2375, 5678, 9229):
                exposed_db_debugger += 20
            elif port in (3000, 4000, 5000, 5173, 8080, 8888, 8000):
                exposed_dev_servers += 10
            elif p.get("severity") in ("CRITICAL", "HIGH"):
                exposed_db_debugger += 20
            else:
                exposed_other += 5

    score -= min(40, exposed_db_debugger)
    score -= min(20, exposed_dev_servers)
    score -= min(15, exposed_other)

    for t in host_obs.get("threats", []):
        sev = t.get("severity", "MEDIUM").upper()
        if sev == "CRITICAL":
            score -= 30
        elif sev == "HIGH":
            score -= 20
        elif sev == "MEDIUM":
            score -= 10

    hygiene = host_obs.get("hygiene", {})
    if hygiene.get("ssh_keys", {}).get("status") == "FAIL":
        score -= 25
    if hygiene.get("workspace_secrets", {}).get("status") == "FAIL":
        score -= 15

    score = max(0, min(100, score))

    if score >= 95:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    else:
        grade = "F"

    bar_width = 20
    filled = int(round((score / 100.0) * bar_width))
    bar = "█" * filled + "░" * (bar_width - filled)

    return score, grade, bar


def format_host_observation_table(obs: dict) -> str:
    """Format local host security posture as a Trivy-style Unicode box table."""
    score = obs.get("score", 100)
    grade = obs.get("grade", "A+")
    bar = obs.get("score_bar", "█" * 20)

    grade_color = (
        ANSI_GREEN + ANSI_BOLD
        if grade in ("A+", "A")
        else (ANSI_CYAN if grade == "B" else (ANSI_YELLOW if grade == "C" else ANSI_RED + ANSI_BOLD))
    )
    colored_grade = color_text(f"GRADE: {grade}", grade_color)
    score_bar_colored = color_text(
        bar,
        ANSI_GREEN if score >= 85 else (ANSI_CYAN if score >= 75 else (ANSI_YELLOW if score >= 60 else ANSI_RED)),
    )

    hostname = obs.get("hostname", socket.gethostname())
    ip = obs.get("ip", "127.0.0.1")
    net = obs.get("network", {})
    p_if = net.get("primary_interface", "lo")
    rx_tot = format_bytes(net.get("rx_bytes", 0))
    tx_tot = format_bytes(net.get("tx_bytes", 0))

    lines = []
    lines.append(color_text(BANNER.strip(), ANSI_CYAN))
    lines.append("")
    lines.append(
        f" Target: {color_text(f'Local Host ({hostname} | {ip})', ANSI_BOLD)}  |  Interface: {p_if} (▼ {rx_tot} RX / ▲ {tx_tot} TX)"
    )
    lines.append(f" Security Score: [{score_bar_colored}] {color_text(f'{score}/100', ANSI_BOLD)}  ({colored_grade})")
    lines.append("")

    lines.append("┌" + "─" * 29 + "┬" + "─" * 16 + "┬" + "─" * 12 + "┬" + "─" * 48 + "┐")
    lines.append(f"│ {'CATEGORY / CHECK':<27} │ {'STATUS':<14} │ {'SEVERITY':<10} │ {'DETAILS / PROCESS':<46} │")
    lines.append("├" + "─" * 29 + "┼" + "─" * 16 + "┼" + "─" * 12 + "┼" + "─" * 48 + "┤")

    pass_count = 0
    warn_count = 0
    risk_count = 0

    def add_row(cat: str, status_text: str, badge_col: str, sev_text: str, sev_col: str, details: str):
        badge = color_text(f"[ {status_text:^8} ]", badge_col)
        sev_badge = color_text(f"{sev_text:^10}", sev_col)
        cat_str = cat if len(cat) <= 27 else cat[:24] + "..."
        det = details if len(details) <= 46 else details[:43] + "..."
        lines.append(f"│ {cat_str:<27} │ {pad_ansi(badge, 14)} │ {pad_ansi(sev_badge, 10)} │ {det:<46} │")

    # 1. Exposed Listening Ports
    l_ports = obs.get("listening_ports", [])
    exposed_ports = [p for p in l_ports if p.get("exposure") == "EXPOSED"]
    local_ports = [p for p in l_ports if p.get("exposure") == "LOCAL"]

    if exposed_ports:
        for p in exposed_ports:
            risk_count += 1
            b_addr = p.get("bind_address", "0.0.0.0")
            formatted_ap = f"[{b_addr}]:{p.get('port')}" if ":" in b_addr else f"{b_addr}:{p.get('port')}"
            if len(formatted_ap) > 14:
                port_label = f"Exposed Port :{p.get('port')}"
            else:
                port_label = f"Exposed Port {formatted_ap}"
            sev = p.get("severity", "MEDIUM")
            sev_col = ANSI_RED + ANSI_BOLD if sev in ("CRITICAL", "HIGH") else ANSI_YELLOW + ANSI_BOLD
            procs = p.get("processes", [])
            proc_desc = f" ({procs[0]['name']})" if procs else ""
            det_desc = f"{p.get('service')}{proc_desc} bound to all interfaces"
            add_row(port_label, "EXPOSED", ANSI_RED + ANSI_BOLD, sev, sev_col, det_desc)
    else:
        pass_count += 1
        add_row("Exposed Listening Ports", "CLEAN", ANSI_GREEN + ANSI_BOLD, "INFO", ANSI_BLUE, "0 ports bound to 0.0.0.0 or * (safe)")

    # 2. Localhost Ports
    pass_count += 1
    if local_ports:
        samples = [f":{p['port']} {p.get('service', '')[:10]}" for p in local_ports[:3]]
        sample_str = f"127.0.0.1 ({', '.join(samples)})"
    else:
        sample_str = "No active loopback listeners"
    add_row(f"Localhost Ports ({len(local_ports)} active)", "SAFE", ANSI_GREEN + ANSI_BOLD, "INFO", ANSI_BLUE, sample_str)

    # 3. Established Outbound Connections
    e_conns = obs.get("established_connections", [])
    plain_cnt = sum(1 for c in e_conns if c.get("remote_port") in (80, 21, 23))
    if plain_cnt > 0:
        warn_count += 1
        add_row(f"Outbound Conns ({len(e_conns)})", "WARN", ANSI_YELLOW + ANSI_BOLD, "MEDIUM", ANSI_YELLOW + ANSI_BOLD, f"{plain_cnt} unencrypted connection(s) active")
    else:
        pass_count += 1
        proc_names = list({c["processes"][0]["name"] for c in e_conns if c.get("processes")})[:3]
        proc_str = f" ({', '.join(proc_names)})" if proc_names else ""
        add_row(f"Outbound Conns ({len(e_conns)})", "NORMAL", ANSI_GREEN + ANSI_BOLD, "INFO", ANSI_BLUE, f"All {len(e_conns)} ESTABLISHED conns over TLS{proc_str}")

    # 4. Malicious / Backdoor Radar
    threats = obs.get("threats", [])
    if threats:
        risk_count += len(threats)
        t = threats[0]
        sev = t.get("severity", "HIGH")
        sev_col = ANSI_RED + ANSI_BOLD if sev in ("CRITICAL", "HIGH") else ANSI_YELLOW + ANSI_BOLD
        add_row("Malicious / Backdoor Radar", "ALERT", ANSI_RED + ANSI_BOLD, sev, sev_col, t.get("details", "Threat identified"))
    else:
        pass_count += 1
        add_row("Malicious / Backdoor Radar", "CLEAN", ANSI_GREEN + ANSI_BOLD, "INFO", ANSI_BLUE, "0 C2/miner ports, 0 SYN floods, 0 plaintext")

    # 5. Workspace & SSH Hygiene
    hygiene = obs.get("hygiene", {})
    ssh_st = hygiene.get("ssh_keys", {}).get("status", "PASS")
    sec_st = hygiene.get("workspace_secrets", {}).get("status", "PASS")
    if ssh_st == "FAIL" or sec_st == "FAIL":
        risk_count += 1
        issues = hygiene.get("ssh_keys", {}).get("issues", []) + hygiene.get("workspace_secrets", {}).get("issues", [])
        issue_str = issues[0] if issues else "Unsafe permissions or unignored secrets"
        add_row("Workspace & SSH Hygiene", "FAIL", ANSI_RED + ANSI_BOLD, "HIGH" if ssh_st == "FAIL" else "MEDIUM", ANSI_RED + ANSI_BOLD, issue_str)
    else:
        pass_count += 1
        add_row("Workspace & SSH Hygiene", "PASS", ANSI_GREEN + ANSI_BOLD, "INFO", ANSI_BLUE, "SSH keys 0600, no untracked .env leaks")

    lines.append("└" + "─" * 29 + "┴" + "─" * 16 + "┴" + "─" * 12 + "┴" + "─" * 48 + "┘")
    lines.append(
        f" Summary: {color_text(f'{pass_count} Passed', ANSI_GREEN)}, {color_text(f'{warn_count} Warnings', ANSI_YELLOW)}, {color_text(f'{risk_count} Exposed / Risks', ANSI_RED if risk_count > 0 else ANSI_GREEN)}"
    )
    return "\n".join(lines)


def compare_host_drift(baseline: dict, live: dict) -> dict:
    """Detect host security drift between a saved laptop baseline and live observation."""
    regressions = []

    base_ports = {}
    for p in baseline.get("listening_ports", []):
        base_ports[(p.get("proto", "tcp"), p.get("port", 0))] = p

    for lp in live.get("listening_ports", []):
        key = (lp.get("proto", "tcp"), lp.get("port", 0))
        port = lp.get("port", 0)
        exposure = lp.get("exposure", "LOCAL")
        bind_addr = lp.get("bind_address", "0.0.0.0")
        service = lp.get("service", "Unknown Service")
        procs = lp.get("processes", [])
        proc_desc = f" ({procs[0]['name']})" if procs else ""

        if key not in base_ports:
            if exposure == "EXPOSED":
                sev = "high" if lp.get("severity") in ("CRITICAL", "HIGH") else "medium"
                regressions.append({
                    "control": f"Exposed Port {bind_addr}:{port}",
                    "severity": sev,
                    "baseline": "closed / inactive",
                    "observed": f"{bind_addr}:{port} (EXPOSED)",
                    "details": f"Newly opened exposed port running {service}{proc_desc}",
                    "recommendation": f"Verify whether port {port} should be exposed to LAN. Restrict binding to 127.0.0.1 if local-only.",
                })
            elif port in (4444, 1337, 3333, 5555, 6667):
                regressions.append({
                    "control": f"Suspicious Port :{port}",
                    "severity": "high",
                    "baseline": "closed",
                    "observed": f"open (LOCAL)",
                    "details": f"Suspicious backdoor/C2 service listening on port {port}{proc_desc}",
                    "recommendation": "Terminate process immediately and inspect origin.",
                })
        else:
            bp = base_ports[key]
            if bp.get("exposure") == "LOCAL" and exposure == "EXPOSED":
                regressions.append({
                    "control": f"Port Exposure: {port} ({service})",
                    "severity": "high",
                    "baseline": f"{bp.get('bind_address', '127.0.0.1')} (LOCAL)",
                    "observed": f"{bind_addr} (EXPOSED)",
                    "details": f"Port {port} previously restricted to localhost is now open to all interfaces ({bind_addr}){proc_desc}.",
                    "recommendation": f"Reconfigure {service} to bind only to 127.0.0.1 loopback.",
                })

    base_threat_keys = {t.get("category", "") + str(t.get("port", "")) for t in baseline.get("threats", [])}
    for lt in live.get("threats", []):
        t_key = lt.get("category", "") + str(lt.get("port", ""))
        if t_key not in base_threat_keys:
            regressions.append({
                "control": lt.get("category", "Threat Anomaly"),
                "severity": lt.get("severity", "medium").lower(),
                "baseline": "clean",
                "observed": "threat detected",
                "details": lt.get("details", ""),
                "recommendation": lt.get("recommendation", "Inspect network connections and active processes."),
            })

    base_hygiene = baseline.get("hygiene", {})
    live_hygiene = live.get("hygiene", {})

    if (
        base_hygiene.get("ssh_keys", {}).get("status") == "PASS"
        and live_hygiene.get("ssh_keys", {}).get("status") == "FAIL"
    ):
        regressions.append({
            "control": "SSH Key Permissions",
            "severity": "high",
            "baseline": "0600 (PASS)",
            "observed": "wider than 0600 (FAIL)",
            "details": live_hygiene.get("ssh_keys", {}).get("details", "SSH private keys have unsafe permissions"),
            "recommendation": "Run 'chmod 600 ~/.ssh/id_*' to secure private keys.",
        })

    if (
        base_hygiene.get("workspace_secrets", {}).get("status") == "PASS"
        and live_hygiene.get("workspace_secrets", {}).get("status") == "FAIL"
    ):
        regressions.append({
            "control": "Workspace Secrets Hygiene",
            "severity": "medium",
            "baseline": "clean (PASS)",
            "observed": "unignored secrets found (FAIL)",
            "details": live_hygiene.get("workspace_secrets", {}).get("details", "Unignored or tracked secrets found"),
            "recommendation": "Add .env files to .gitignore and untrack from git repository.",
        })

    return {
        "target": "localhost",
        "type": "host",
        "drift_detected": len(regressions) > 0,
        "regressions_count": len(regressions),
        "regressions": regressions,
        "live": live,
        "baseline": baseline,
    }


def format_host_compare_table(diff: dict) -> str:
    """Format host baseline drift comparison as a Trivy-style table."""
    lines = []
    hostname = diff.get("live", {}).get("hostname") or diff.get("baseline", {}).get("hostname", "localhost")
    ip = diff.get("live", {}).get("ip", "127.0.0.1")
    base_saved = diff["baseline"].get("saved_at", "Unknown")
    now_time = diff["live"].get("timestamp", datetime.datetime.now(datetime.timezone.utc).isoformat())

    lines.append(color_text(BANNER.strip(), ANSI_CYAN))
    lines.append("")
    lines.append(f" Target: {color_text(f'Local Host ({hostname} | {ip})', ANSI_BOLD)}")
    lines.append(f" Baseline Saved: {base_saved}  |  Current Time: {now_time}")
    lines.append("")

    lines.append("┌" + "─" * 29 + "┬" + "─" * 16 + "┬" + "─" * 16 + "┬" + "─" * 12 + "┬" + "─" * 10 + "┐")
    lines.append(f"│ {'CONTROL / PORT':<27} │ {'BASELINE':<14} │ {'CURRENT':<14} │ {'STATUS':<10} │ {'SEVERITY':<8} │")
    lines.append("├" + "─" * 29 + "┼" + "─" * 16 + "┼" + "─" * 16 + "┼" + "─" * 12 + "┼" + "─" * 10 + "┤")

    for r in diff.get("regressions", []):
        ctrl = r["control"] if len(r["control"]) <= 27 else r["control"][:24] + "..."
        base_v = r["baseline"] if len(r["baseline"]) <= 14 else r["baseline"][:11] + "..."
        curr_v = r["observed"] if len(r["observed"]) <= 14 else r["observed"][:11] + "..."
        st_badge = pad_ansi(color_text("DRIFT", ANSI_RED + ANSI_BOLD), 10)
        sev_badge = pad_ansi(severity_badge(r["severity"]), 8)
        lines.append(f"│ {ctrl:<27} │ {base_v:<14} │ {curr_v:<14} │ {st_badge} │ {sev_badge} │")

    if not diff.get("regressions"):
        lines.append(
            f"│ {'Host Security Controls':<27} │ {'Baseline State':<14} │ {'Matching Live':<14} │ {pad_ansi(color_text('MATCH', ANSI_GREEN), 10)} │ {pad_ansi('-', 8)} │"
        )

    lines.append("└" + "─" * 29 + "┴" + "─" * 16 + "┴" + "─" * 16 + "┴" + "─" * 12 + "┴" + "─" * 10 + "┘")

    if diff.get("drift_detected"):
        lines.append(
            color_text(
                f"\n⚠ DRIFT DETECTED: {diff['regressions_count']} host security regression(s) identified!",
                ANSI_RED + ANSI_BOLD,
            )
        )
        lines.append("\nRecommended Actions:")
        for idx, r in enumerate(diff["regressions"], 1):
            lines.append(
                f"  {idx}. [{r['severity'].upper()}] {r['control']}: {r['recommendation']}"
            )
    else:
        lines.append(
            color_text(
                "\n✔ No security drift detected. All host controls match or exceed baseline.",
                ANSI_GREEN + ANSI_BOLD,
            )
        )

    return "\n".join(lines)


def generate_host_issue_content(diff: dict) -> tuple[str, str]:
    """Format GitHub Issue title and body for local host security regressions."""
    hostname = diff.get("live", {}).get("hostname", socket.gethostname())
    ip = diff.get("live", {}).get("ip", "127.0.0.1")
    regressions = diff.get("regressions", [])
    title = f"[NETRA Host Incident] {hostname}: {len(regressions)} security regression(s) detected"

    timestamp = diff.get("live", {}).get("timestamp")
    baseline_saved = diff.get("baseline", {}).get("saved_at")

    body_lines = [
        "## NETRA Host Security Incident Alert",
        "",
        f"**Target Host:** `{hostname} ({ip})`  ",
        f"**Detected At:** `{timestamp}`  ",
        f"**Baseline Anchor:** `{baseline_saved}`  ",
        f"**Total Regressions:** `{len(regressions)}`  ",
        "",
        "### Security Regressions Summary",
        "",
        "| Control | Severity | Baseline | Current | Recommendation |",
        "|---|---|---|---|---|",
    ]

    for r in regressions:
        body_lines.append(
            f"| **{r['control']}** | `{r['severity'].upper()}` | `{r['baseline']}` | `{r['observed']}` | {r['recommendation']} |"
        )

    body_lines.extend(
        [
            "",
            "### Action Required",
            f"A host security regression was detected on developer machine `{hostname}`. Newly opened listening ports or unauthorized connections expose your local environment. Review the recommendations above immediately.",
            "",
            "---",
            "*Dispatched automatically by [NETRA_CLI](https://github.com/404Avinash/Netra_cli) via Swytchcode Execution Authority Kernel.*",
        ]
    )

    return title, "\n".join(body_lines)


def run_host_top_dashboard(interval: float = 3.0) -> int:
    """Launch interactive btop-style curses terminal monitoring dashboard for local host."""
    if not sys.stdin.isatty():
        sys.stderr.write("Error: 'top' dashboard requires an interactive terminal (TTY).\n")
        return 1

    try:
        import curses
    except ImportError:
        sys.stderr.write(
            "Error: 'curses' module not available. Built-in on Linux/macOS. On Windows, install 'windows-curses'.\n"
        )
        return 1

    def curses_host_main(stdscr):
        try:
            curses.curs_set(0)
        except curses.error:
            pass

        stdscr.nodelay(True)
        stdscr.timeout(500)
        if curses.has_colors():
            curses.start_color()
            try:
                curses.use_default_colors()
            except curses.error:
                pass
            curses.init_pair(1, curses.COLOR_GREEN, -1)
            curses.init_pair(2, curses.COLOR_RED, -1)
            curses.init_pair(3, curses.COLOR_YELLOW, -1)
            curses.init_pair(4, curses.COLOR_CYAN, -1)
            curses.init_pair(5, curses.COLOR_BLUE, -1)

            col_pass = curses.color_pair(1) | curses.A_BOLD
            col_fail = curses.color_pair(2) | curses.A_BOLD
            col_warn = curses.color_pair(3) | curses.A_BOLD
            col_cyan = curses.color_pair(4) | curses.A_BOLD
            col_blue = curses.color_pair(5)
        else:
            col_pass = curses.A_BOLD
            col_fail = curses.A_BOLD
            col_warn = curses.A_NORMAL
            col_cyan = curses.A_BOLD
            col_blue = curses.A_NORMAL

        last_poll = 0.0
        obs = None
        diff = None
        status_msg = f"Host radar active (Refresh every {interval:.1f}s) | Press 'q' to quit"
        status_msg_time = time.time()

        while True:
            now = time.time()
            if obs is None or (now - last_poll >= interval):
                last_poll = now
                try:
                    obs = inspect_local_host(sample_duration=0.1)
                    filepath = get_baseline_filepath("localhost")
                    if filepath.exists():
                        try:
                            baseline = load_baseline(filepath)
                            diff = compare_drift(baseline, obs)
                        except Exception:
                            diff = None
                    else:
                        diff = None
                except Exception as e:
                    obs = {
                        "error": str(e),
                        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    }
                    diff = None

            max_y, max_x = stdscr.getmaxyx()
            stdscr.erase()

            if max_y < 22 or max_x < 76:
                msg = f"Terminal size too small ({max_x}x{max_y}). Expand window to at least 76x22."
                try:
                    stdscr.addstr(0, 0, msg[: max_x - 1], col_warn)
                except curses.error:
                    pass
            else:
                def draw(y, x, text, attr=0):
                    if 0 <= y < max_y and 0 <= x < max_x:
                        avail = max_x - 1 - x
                        if avail > 0:
                            try:
                                stdscr.addstr(y, x, text[:avail], attr)
                            except curses.error:
                                pass

                draw(0, 0, "┌" + "─" * (max_x - 2) + "┐")
                h_name = obs.get("hostname", socket.gethostname())
                h_ip = obs.get("ip", "127.0.0.1")
                title_bar = f" NETRA HOST RADAR  ──  [Host: {h_name} | IP: {h_ip}] "
                draw(0, 4, title_bar, col_cyan)

                if "error" in obs:
                    draw(2, 2, f"Error inspecting host: {obs['error']}", col_fail)
                else:
                    score = obs.get("score", 100)
                    grade = obs.get("grade", "A+")
                    bar = obs.get("score_bar", "█" * 20)
                    grade_color = (
                        col_pass
                        if grade in ("A+", "A")
                        else (col_cyan if grade == "B" else (col_warn if grade == "C" else col_fail))
                    )
                    draw(2, 2, f"Security Score: [{bar}] {score}/100", curses.A_BOLD)
                    draw(2, 42, f"GRADE: {grade}", grade_color)

                    net = obs.get("network", {})
                    p_if = net.get("primary_interface", "lo")
                    rx_rate = format_rate(net.get("rx_rate_bps", 0.0))
                    tx_rate = format_rate(net.get("tx_rate_bps", 0.0))
                    rx_tot = format_bytes(net.get("rx_bytes", 0))
                    tx_tot = format_bytes(net.get("tx_bytes", 0))
                    draw(2, 58, f"If: {p_if} (▼{rx_tot}/▲{tx_tot})", col_blue)

                    rx_bps = net.get("rx_rate_bps", 0.0)
                    tx_bps = net.get("tx_rate_bps", 0.0)
                    rx_ratio = min(rx_bps / (1024 * 1024), 1.0)
                    tx_ratio = min(tx_bps / (1024 * 1024), 1.0)
                    g_len = 16
                    rx_filled = int(round(rx_ratio * g_len))
                    tx_filled = int(round(tx_ratio * g_len))
                    rx_bar = "█" * rx_filled + "░" * (g_len - rx_filled)
                    tx_bar = "█" * tx_filled + "░" * (g_len - tx_filled)
                    draw(3, 2, f"Bandwidth: ▼ RX [{rx_bar}] {rx_rate}   ▲ TX [{tx_bar}] {tx_rate}")

                    draw(4, 0, "├" + "─" * (max_x - 2) + "┤")
                    draw(5, 2, "EXPOSED & LISTENING PORTS (LAN EXPOSURE AUDIT)", col_cyan)
                    draw(
                        6,
                        2,
                        f"{'PORT':<7} {'PROTO':<6} {'BIND ADDR':<16} {'EXPOSURE':<12} {'SEVERITY':<10} {'SERVICE / PROCESS':<30}",
                        curses.A_BOLD,
                    )

                    l_ports = obs.get("listening_ports", [])
                    curr_y = 7
                    for lp in l_ports[:7]:
                        port_str = str(lp.get("port", 0))
                        proto_str = lp.get("proto", "tcp")
                        b_addr = lp.get("bind_address", "0.0.0.0")
                        exp_str = lp.get("exposure", "LOCAL")
                        sev_str = lp.get("severity", "INFO")
                        svc_str = lp.get("service", "Service")
                        procs = lp.get("processes", [])
                        proc_str = f" ({procs[0]['name']})" if procs else ""
                        details_str = f"{svc_str}{proc_str}"

                        exp_col = col_fail if exp_str == "EXPOSED" else col_pass
                        sev_col = (
                            col_fail
                            if sev_str in ("CRITICAL", "HIGH")
                            else (col_warn if sev_str == "MEDIUM" else col_blue)
                        )
                        draw(curr_y, 2, f"{port_str:<7} {proto_str:<6} {b_addr:<16}")
                        draw(curr_y, 33, f"[{exp_str:^8}]", exp_col)
                        draw(curr_y, 46, f"{sev_str:<10}", sev_col)
                        draw(curr_y, 57, details_str[: max_x - 59])
                        curr_y += 1

                    draw(curr_y, 0, "├" + "─" * (max_x - 2) + "┤")
                    curr_y += 1
                    draw(curr_y, 2, "ACTIVE PROCESS CONNECTIONS (ESTABLISHED)", col_cyan)
                    curr_y += 1
                    draw(
                        curr_y,
                        2,
                        f"{'PROCESS (PID)':<22} {'LOCAL SOCKET':<24} {'REMOTE SOCKET':<24} {'SERVICE':<16}",
                        curses.A_BOLD,
                    )
                    curr_y += 1

                    e_conns = obs.get("established_connections", [])
                    for ec in e_conns[: max(1, max_y - curr_y - 6)]:
                        procs = ec.get("processes", [])
                        p_name = f"{procs[0]['name']} ({procs[0]['pid']})" if procs else "-"
                        l_sock = ec.get("local_address", "")
                        r_sock = ec.get("remote_address", "")
                        svc = ec.get("service", "")
                        draw(curr_y, 2, f"{p_name:<22} {l_sock:<24} {r_sock:<24} {svc[: max_x - 74]}")
                        curr_y += 1

                    draw(max_y - 4, 0, "├" + "─" * (max_x - 2) + "┤")
                    if diff is None:
                        draw(
                            max_y - 3,
                            2,
                            "Baseline: No laptop baseline locked yet. (Press 's' to lock baseline snapshot)",
                            col_warn,
                        )
                    else:
                        saved_at = diff["baseline"].get("saved_at", "")[:19]
                        if diff.get("drift_detected"):
                            reg_cnt = len(diff.get("regressions", []))
                            draw(
                                max_y - 3,
                                2,
                                f"▲ BASELINE DRIFT DETECTED: {reg_cnt} regression(s) vs baseline saved {saved_at}",
                                col_fail,
                            )
                        else:
                            draw(
                                max_y - 3,
                                2,
                                f"✔ BASELINE MATCH: All ports and host controls match baseline (saved {saved_at})",
                                col_pass,
                            )

                draw(max_y - 2, 0, "├" + "─" * (max_x - 2) + "┤")
                hotkeys = "HOTKEYS: [r] Refresh Now   [s] Save Laptop Baseline Snapshot   [q] Quit"
                draw(max_y - 2, 2, hotkeys, curses.A_BOLD)

                if time.time() - status_msg_time > 4.0:
                    status_msg = f"Live host monitoring active (interval: {interval:.1f}s) | Press 'q' to quit"
                draw(max_y - 1, 2, status_msg, col_cyan)
                draw(max_y - 1, 0, "└")
                draw(max_y - 1, max_x - 1, "┘")

            stdscr.refresh()

            try:
                ch = stdscr.getch()
            except curses.error:
                ch = -1

            if ch in (ord("q"), ord("Q"), 27):
                break
            elif ch in (ord("r"), ord("R")):
                status_msg = "Refreshing host telemetry..."
                status_msg_time = time.time()
                obs = None
            elif ch in (ord("s"), ord("S")):
                if obs and "error" not in obs:
                    filepath = get_baseline_filepath("localhost")
                    save_baseline(obs, filepath=filepath, auto_confirm=True)
                    try:
                        baseline = load_baseline(filepath)
                        diff = compare_drift(baseline, obs)
                    except Exception:
                        pass
                    status_msg = f"✔ Laptop baseline snapshot saved to {filepath}!"
                    status_msg_time = time.time()

        return 0

    try:
        curses.wrapper(curses_host_main)
    except KeyboardInterrupt:
        pass
    return 0


def calculate_security_score(obs: dict) -> tuple[int, str, str]:
    """
    Calculate an objective 0-100 security score, letter grade, and progress meter.
    Weights:
      - HTTP->HTTPS Redirect: 25 pts
      - TLS Certificate Validity: 25 pts
      - Strict-Transport-Security (HSTS): 20 pts
      - Content-Security-Policy (CSP): 15 pts
      - X-Content-Type-Options: 10 pts
      - Referrer-Policy: 5 pts
    """
    score = 0
    # Redirect (25 pts)
    r_st = obs.get("redirect", {}).get("status")
    if r_st == "pass":
        score += 25
    elif r_st == "inconclusive":
        score += 10

    # TLS (25 pts)
    t_st = obs.get("tls", {}).get("status")
    if t_st == "pass":
        score += 25
    elif t_st == "inconclusive":
        score += 10

    # Headers (50 pts total)
    hdrs = obs.get("headers", {})
    hsts_st = hdrs.get("Strict-Transport-Security", {}).get("status")
    if hsts_st == "present":
        score += 20
    elif hsts_st == "inconclusive":
        score += 10

    csp_st = hdrs.get("Content-Security-Policy", {}).get("status")
    if csp_st == "present":
        score += 15
    elif csp_st == "inconclusive":
        score += 7

    xcto_st = hdrs.get("X-Content-Type-Options", {}).get("status")
    if xcto_st == "present":
        score += 10
    elif xcto_st == "inconclusive":
        score += 5

    ref_st = hdrs.get("Referrer-Policy", {}).get("status")
    if ref_st == "present":
        score += 5
    elif ref_st == "inconclusive":
        score += 2

    # Grade scale
    if score >= 95:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    else:
        grade = "F"

    # 20-character progress bar
    bar_width = 20
    filled = int(round((score / 100.0) * bar_width))
    bar = "█" * filled + "░" * (bar_width - filled)

    return score, grade, bar



# Input Validation
def validate_url(url_str: str) -> str:
    """
    Validate and normalize target URL format.
    Must contain scheme (http or https) and a valid netloc/hostname.
    If scheme is missing (e.g. example.com), automatically prepends https://.
    """
    if not url_str or not isinstance(url_str, str):
        raise ValueError("Target URL cannot be empty.")

    url_str = url_str.strip()
    if not url_str:
        raise ValueError("Target URL cannot be empty.")

    # Auto-normalize target URLs lacking a scheme (nmap-style ergonomics)
    if "://" not in url_str:
        url_str = f"https://{url_str}"

    parsed = urllib.parse.urlparse(url_str)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(
            f"Invalid URL scheme '{parsed.scheme}'. Target must start with http:// or https://"
        )
    if not parsed.netloc or not parsed.hostname:
        raise ValueError(f"Invalid target URL '{url_str}'. Must include a valid hostname.")

    hostname = parsed.hostname.lower()
    if "." not in hostname and ":" not in hostname and hostname != "localhost":
        raise ValueError(f"Invalid target URL '{url_str}'. Must include a valid hostname.")

    return url_str


def validate_repo(repo_str: str) -> tuple[str, str]:
    """
    Validate GitHub repository string in OWNER/REPO format.
    """
    if not repo_str or not isinstance(repo_str, str):
        raise ValueError("Repository cannot be empty. Expected OWNER/REPO.")

    parts = repo_str.strip().split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f"Invalid repository '{repo_str}'. Expected format: OWNER/REPO")

    owner, repo = parts[0], parts[1]
    name_pattern = re.compile(r"^[A-Za-z0-9_.-]+$")
    if not name_pattern.match(owner) or not name_pattern.match(repo):
        raise ValueError(
            f"Repository '{repo_str}' contains invalid characters. Use alphanumeric, '.', '-', or '_'."
        )

    return owner, repo


def get_baseline_filepath(target_url: str) -> Path:
    """Generate deterministic baseline file path for a target URL or local host."""
    if is_local_target(target_url):
        return Path(".netra/baselines/localhost.json")

    parsed = urllib.parse.urlparse(target_url)
    hostname = (parsed.hostname or "unknown").lower()
    port_suffix = f"_{parsed.port}" if parsed.port and parsed.port not in (80, 443) else ""
    safe_name = re.sub(r"[^a-z0-9.-]", "_", hostname) + port_suffix
    return Path("baselines") / f"{safe_name}.json"


# Inspection Engine
def check_redirect(
    target_url: str, timeout: float = 10.0, max_hops: int = 5
) -> dict:
    """
    Verify whether plaintext HTTP redirects to HTTPS.
    Connects to HTTP (port 80 or user-specified port) and follows redirect hops
    (up to max_hops) to ensure it cleanly reaches HTTPS.
    """
    parsed = urllib.parse.urlparse(target_url)
    hostname = parsed.hostname
    if not hostname:
        return {"status": "inconclusive", "details": "Unable to extract hostname from target URL"}

    http_port = parsed.port if (parsed.scheme == "http" and parsed.port) else 80
    request_path = parsed.path if parsed.path else "/"
    if parsed.query:
        request_path += f"?{parsed.query}"

    current_url = f"http://{hostname}"
    if http_port != 80:
        current_url += f":{http_port}"
    current_url += request_path

    visited = set()
    chain = []

    for _ in range(max_hops):
        if current_url in visited:
            return {
                "status": "fail",
                "details": f"Redirect loop detected: {' -> '.join(chain)} -> {current_url}",
            }
        visited.add(current_url)

        curr_parsed = urllib.parse.urlparse(current_url)
        curr_host = curr_parsed.hostname
        curr_port = curr_parsed.port or (443 if curr_parsed.scheme == "https" else 80)
        curr_path = curr_parsed.path or "/"
        if curr_parsed.query:
            curr_path += f"?{curr_parsed.query}"

        if curr_parsed.scheme == "https":
            if chain:
                return {
                    "status": "pass",
                    "details": f"Redirected to HTTPS: {' -> '.join(chain)} -> {current_url}",
                }
            return {
                "status": "pass",
                "details": f"HTTPS endpoint reached: {current_url}",
            }

        try:
            conn = http.client.HTTPConnection(curr_host, port=curr_port, timeout=timeout)
            headers = {"Host": curr_host, "User-Agent": f"Netra-CLI/{VERSION}"}

            conn.request("HEAD", curr_path, headers=headers)
            resp = conn.getresponse()
            status = resp.status
            location = resp.getheader("Location")
            conn.close()

            # If HEAD returned 405 Method Not Allowed, fallback to GET
            if status == 405:
                conn = http.client.HTTPConnection(curr_host, port=curr_port, timeout=timeout)
                conn.request("GET", curr_path, headers=headers)
                resp = conn.getresponse()
                status = resp.status
                location = resp.getheader("Location")
                conn.close()

            chain.append(f"{status} ({current_url})")

            if status in (301, 302, 303, 307, 308) and location:
                clean_location = location.strip()
                next_url = urllib.parse.urljoin(current_url, clean_location)
                next_parsed = urllib.parse.urlparse(next_url)
                if next_parsed.scheme == "https":
                    return {
                        "status": "pass",
                        "details": f"HTTP {status} redirects to HTTPS: {next_url}",
                    }
                else:
                    return {
                        "status": "fail",
                        "details": f"HTTP {status} redirects to non-HTTPS location: {clean_location}",
                    }
            elif status == 200:
                return {
                    "status": "fail",
                    "details": f"HTTP 200 OK served over plaintext at {current_url} without HTTPS redirection",
                }
            else:
                return {
                    "status": "fail",
                    "details": f"HTTP returned status {status} at {current_url} without redirect to HTTPS",
                }

        except (socket.timeout, TimeoutError):
            return {
                "status": "inconclusive",
                "details": f"Network timeout connecting to HTTP port {curr_port} on {curr_host}",
            }
        except (socket.gaierror, ConnectionRefusedError, OSError) as e:
            return {
                "status": "inconclusive",
                "details": f"Network connection error on HTTP port {curr_port} ({curr_host}): {e}",
            }

    return {
        "status": "fail",
        "details": f"Exceeded maximum redirect hops ({max_hops}) without reaching HTTPS: {' -> '.join(chain)}",
    }


def check_tls(hostname: str, port: int = 443, timeout: float = 10.0) -> dict:
    """
    Inspect TLS certificate validity, expiration date, and calculate remaining days.
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        if not cert or "notAfter" not in cert:
            return {
                "status": "inconclusive",
                "days_remaining": None,
                "expiry": None,
                "issuer": None,
                "details": "Certificate peer details missing or empty",
            }

        expiry_epoch = ssl.cert_time_to_seconds(cert["notAfter"])
        expiry_dt = datetime.datetime.fromtimestamp(expiry_epoch, tz=datetime.timezone.utc)
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        remaining_seconds = (expiry_dt - now_dt).total_seconds()
        iso_expiry = expiry_dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Extract certificate issuer
        issuer_dict = {}
        for item in cert.get("issuer", ()):
            for key, val in item:
                issuer_dict[key] = val
        issuer = (
            issuer_dict.get("organizationName")
            or issuer_dict.get("commonName")
            or "Unknown Authority"
        )

        if expiry_dt > now_dt:
            # Valid certificate
            days_remaining = max(1, int(remaining_seconds / 86400)) if remaining_seconds >= 86400 else 0
            if remaining_seconds < 86400:
                hours_left = max(0, int(remaining_seconds / 3600))
                details = f"Valid certificate ({hours_left} hours left, expires {iso_expiry}, issuer: {issuer})"
            else:
                details = f"Valid certificate ({days_remaining} days left, expires {iso_expiry}, issuer: {issuer})"
            return {
                "status": "pass",
                "days_remaining": days_remaining,
                "expiry": iso_expiry,
                "issuer": issuer,
                "details": details,
            }
        else:
            # Expired certificate
            days_expired = abs(int(remaining_seconds / 86400))
            return {
                "status": "fail",
                "days_remaining": -days_expired if days_expired > 0 else 0,
                "expiry": iso_expiry,
                "issuer": issuer,
                "details": f"Certificate EXPIRED {days_expired} days ago on {iso_expiry}",
            }

    except ssl.SSLCertVerificationError as e:
        err_msg = e.strerror or str(e)
        is_expired = "expired" in err_msg.lower()
        return {
            "status": "fail",
            "days_remaining": 0 if is_expired else None,
            "expiry": None,
            "issuer": None,
            "details": f"TLS verification error: {err_msg}",
        }
    except (socket.timeout, TimeoutError):
        return {
            "status": "inconclusive",
            "days_remaining": None,
            "expiry": None,
            "issuer": None,
            "details": f"Connection timed out reaching TLS port {port}",
        }
    except (ssl.SSLError, socket.gaierror, ConnectionRefusedError, OSError) as e:
        return {
            "status": "inconclusive",
            "days_remaining": None,
            "expiry": None,
            "issuer": None,
            "details": f"TLS handshake/connection error: {e}",
        }


def check_headers(target_url: str, timeout: float = 10.0) -> dict:
    """
    Inspect HTTP response headers over HTTPS for key security controls:
    HSTS, CSP, X-Content-Type-Options, Referrer-Policy.
    """
    parsed = urllib.parse.urlparse(target_url)
    https_url = urllib.parse.urlunparse(
        ("https", parsed.netloc, parsed.path or "/", parsed.params, parsed.query, parsed.fragment)
    )

    headers_result = {
        "Strict-Transport-Security": {"status": "missing", "value": None},
        "Content-Security-Policy": {"status": "missing", "value": None},
        "X-Content-Type-Options": {"status": "missing", "value": None},
        "Referrer-Policy": {"status": "missing", "value": None},
    }

    try:
        req = urllib.request.Request(https_url, headers={"User-Agent": f"Netra-CLI/{VERSION}"})
        ctx = ssl.create_default_context()

        resp_headers = None
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
                resp_headers = response.headers
        except urllib.error.HTTPError as e:
            # HTTP errors (401, 403, 404, 500) still carry server security headers
            resp_headers = e.headers
        except urllib.error.URLError as e:
            # If TLS certificate verification failed, retry with unverified context
            # so we can still inspect server security headers (e.g. self-signed/staging certs)
            if isinstance(e.reason, (ssl.SSLCertVerificationError, ssl.SSLError)):
                unverified_ctx = ssl._create_unverified_context()
                try:
                    with urllib.request.urlopen(req, timeout=timeout, context=unverified_ctx) as response:
                        resp_headers = response.headers
                except urllib.error.HTTPError as e2:
                    resp_headers = e2.headers
            else:
                raise

        if resp_headers is not None:
            # 1. Strict-Transport-Security
            hsts = resp_headers.get("Strict-Transport-Security")
            if hsts and hsts.strip():
                hsts_val = hsts.strip()
                m = re.search(r"\bmax-age=(\d+)", hsts_val, re.IGNORECASE)
                if m:
                    max_age = int(m.group(1))
                    if max_age == 0:
                        headers_result["Strict-Transport-Security"] = {
                            "status": "fail",
                            "value": hsts_val,
                            "details": "max-age=0 explicitly disables HSTS protection",
                        }
                    else:
                        headers_result["Strict-Transport-Security"] = {
                            "status": "present",
                            "value": hsts_val,
                        }
                else:
                    headers_result["Strict-Transport-Security"] = {
                        "status": "fail",
                        "value": hsts_val,
                        "details": "Missing required max-age directive",
                    }

            # 2. Content-Security-Policy
            csp = resp_headers.get("Content-Security-Policy")
            if csp and csp.strip():
                headers_result["Content-Security-Policy"] = {
                    "status": "present",
                    "value": csp.strip(),
                }

            # 3. X-Content-Type-Options (must be 'nosniff')
            xcto = resp_headers.get("X-Content-Type-Options")
            if xcto and xcto.strip():
                val = xcto.strip()
                if "nosniff" in val.lower():
                    headers_result["X-Content-Type-Options"] = {
                        "status": "present",
                        "value": val,
                    }
                else:
                    headers_result["X-Content-Type-Options"] = {
                        "status": "fail",
                        "value": val,
                    }

            # 4. Referrer-Policy
            ref = resp_headers.get("Referrer-Policy")
            if ref and ref.strip():
                headers_result["Referrer-Policy"] = {
                    "status": "present",
                    "value": ref.strip(),
                }

            return headers_result

    except (socket.timeout, TimeoutError):
        return {
            k: {"status": "inconclusive", "value": None, "error": "Network timeout"}
            for k in headers_result
        }
    except (urllib.error.URLError, socket.gaierror, ConnectionRefusedError, OSError) as e:
        return {
            k: {"status": "inconclusive", "value": None, "error": str(e)}
            for k in headers_result
        }

    return headers_result


def observe(target_url: str, timeout: float = 10.0) -> dict:
    """
    Run full security observation suite against the target URL.
    """
    validated_url = validate_url(target_url)
    parsed = urllib.parse.urlparse(validated_url)
    hostname = parsed.hostname
    tls_port = parsed.port if (parsed.scheme == "https" and parsed.port) else 443
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    redirect = check_redirect(validated_url, timeout=timeout)
    tls = check_tls(hostname, port=tls_port, timeout=timeout)
    headers = check_headers(validated_url, timeout=timeout)

    return {
        "target": validated_url,
        "timestamp": now_iso,
        "redirect": redirect,
        "tls": tls,
        "headers": headers,
    }


# Baseline Engine
def save_baseline(
    observation: dict, filepath: Path | None = None, auto_confirm: bool = False
) -> bool:
    """
    Save an observation as a reviewed security baseline.
    """
    target = observation.get("target", "localhost")
    if filepath is None:
        filepath = get_baseline_filepath(target)

    if not auto_confirm:
        confirm_prompt = input(f"Save baseline for '{target}' to {filepath}? [y/N]: ").strip()
        if confirm_prompt.lower() not in ("y", "yes"):
            print("Baseline save aborted by user.")
            return False

    filepath.parent.mkdir(parents=True, exist_ok=True)
    now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if observation.get("type") == "host" or is_local_target(target):
        baseline_payload = {
            "target": "localhost",
            "type": "host",
            "hostname": observation.get("hostname", socket.gethostname()),
            "saved_at": now_iso,
            "reviewed": True,
            "listening_ports": observation.get("listening_ports", []),
            "threats": observation.get("threats", []),
            "hygiene": observation.get("hygiene", {}),
            "score": observation.get("score"),
            "grade": observation.get("grade"),
        }
    else:
        baseline_payload = {
            "target": target,
            "saved_at": now_iso,
            "reviewed": True,
            "redirect": observation.get("redirect"),
            "tls": observation.get("tls"),
            "headers": observation.get("headers"),
        }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(baseline_payload, f, indent=2)

    print(
        color_text(f"✔ Baseline saved successfully to {filepath}", ANSI_GREEN + ANSI_BOLD)
    )
    return True


def load_baseline(filepath: Path) -> dict:
    """
    Load a saved baseline JSON file.
    """
    if not filepath.exists():
        if filepath.name == "localhost.json":
            alt = Path("baselines/localhost.json") if ".netra" in str(filepath) else Path(".netra/baselines/localhost.json")
            if alt.exists():
                filepath = alt
    if not filepath.exists():
        raise FileNotFoundError(
            f"Baseline file not found at '{filepath}'. Run 'netra baseline save' first."
        )
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


# Drift Comparison Engine
def compare_drift(baseline: dict, live: dict) -> dict:
    """
    Detect security drift between a reviewed baseline and live observation.
    Only reports true regressions (controls that were pass/present becoming fail/missing,
    or certificate expiry). Ignores routine renewals or inconclusives.
    """
    if baseline.get("type") == "host" or live.get("type") == "host" or is_local_target(live.get("target")):
        return compare_host_drift(baseline, live)

    regressions = []

    # 1. HTTP -> HTTPS Redirect
    base_red = baseline.get("redirect", {}).get("status")
    live_red = live.get("redirect", {}).get("status")
    if base_red == "pass" and live_red == "fail":
        regressions.append(
            {
                "control": "HTTP->HTTPS Redirect",
                "severity": "medium",
                "baseline": "pass",
                "observed": "fail",
                "details": live.get("redirect", {}).get("details", "Redirect failed"),
                "recommendation": "Enforce permanent 301/308 redirect from HTTP to HTTPS on port 80.",
            }
        )

    # 2. TLS Certificate Validity & Expiration
    base_tls = baseline.get("tls", {}).get("status")
    live_tls = live.get("tls", {}).get("status")
    live_days = live.get("tls", {}).get("days_remaining")

    if base_tls == "pass":
        if live_tls == "fail":
            regressions.append(
                {
                    "control": "TLS Certificate Validity",
                    "severity": "high",
                    "baseline": "valid (>0 days remaining)",
                    "observed": (
                        f"expired ({abs(live_days)} days ago)"
                        if (live_days is not None and live_days < 0)
                        else (
                            "expired"
                            if (live_days == 0 and "EXPIRED" in live.get("tls", {}).get("details", ""))
                            else "fail"
                        )
                    ),
                    "details": live.get("tls", {}).get("details", "TLS validation failed"),
                    "recommendation": "Renew TLS certificate immediately and deploy to web server.",
                }
            )

    # 3. HTTP Security Headers
    header_controls = {
        "Strict-Transport-Security": {
            "severity": "medium",
            "rec": "Restore Strict-Transport-Security header (recommended: max-age=31536000; includeSubDomains).",
        },
        "Content-Security-Policy": {
            "severity": "medium",
            "rec": "Restore Content-Security-Policy header to protect against XSS and content injection.",
        },
        "X-Content-Type-Options": {
            "severity": "low",
            "rec": "Restore 'X-Content-Type-Options: nosniff' header to prevent MIME sniffing.",
        },
        "Referrer-Policy": {
            "severity": "low",
            "rec": "Restore 'Referrer-Policy: strict-origin-when-cross-origin' header to prevent referrer leakage.",
        },
    }

    base_headers = baseline.get("headers", {})
    live_headers = live.get("headers", {})

    for hdr, meta in header_controls.items():
        base_status = base_headers.get(hdr, {}).get("status")
        live_status = live_headers.get(hdr, {}).get("status")

        if base_status == "present" and live_status in ("missing", "fail"):
            regressions.append(
                {
                    "control": hdr,
                    "severity": meta["severity"],
                    "baseline": "present",
                    "observed": live_status,
                    "details": live_headers.get(hdr, {}).get("value")
                    or "Header missing from server response",
                    "recommendation": meta["rec"],
                }
            )

    return {
        "target": live["target"],
        "drift_detected": len(regressions) > 0,
        "regressions_count": len(regressions),
        "regressions": regressions,
        "live": live,
        "baseline": baseline,
    }


# Output Formatting Helpers
def format_observation_table(obs: dict) -> str:
    """Format observation dictionary as a Trivy-style Unicode box table."""
    score, grade, bar = calculate_security_score(obs)
    grade_color = ANSI_GREEN + ANSI_BOLD if grade in ("A+", "A") else (ANSI_CYAN if grade == "B" else (ANSI_YELLOW if grade == "C" else ANSI_RED + ANSI_BOLD))
    colored_grade = color_text(f"GRADE: {grade}", grade_color)
    score_bar_colored = color_text(bar, ANSI_GREEN if score >= 85 else (ANSI_CYAN if score >= 75 else (ANSI_YELLOW if score >= 60 else ANSI_RED)))

    lines = []
    lines.append(color_text(BANNER.strip(), ANSI_CYAN))
    lines.append("")
    lines.append(f" Target: {color_text(obs['target'], ANSI_BOLD)}  |  Timestamp: {obs['timestamp']}")
    lines.append(f" Security Score: [{score_bar_colored}] {color_text(f'{score}/100', ANSI_BOLD)}  ({colored_grade})")
    lines.append("")

    lines.append("┌" + "─" * 29 + "┬" + "─" * 16 + "┬" + "─" * 12 + "┬" + "─" * 48 + "┐")
    lines.append(f"│ {'CONTROL':<27} │ {'STATUS':<14} │ {'SEVERITY':<10} │ {'DETAILS / VALUE':<46} │")
    lines.append("├" + "─" * 29 + "┼" + "─" * 16 + "┼" + "─" * 12 + "┼" + "─" * 48 + "┤")

    pass_count = 0
    warn_count = 0
    fail_count = 0

    def add_row(ctrl: str, status: str, sev: str, details: str):
        nonlocal pass_count, warn_count, fail_count
        st_lower = status.lower()
        if st_lower in ("pass", "present"):
            pass_count += 1
            badge = color_text(f"[ {status.upper():^8} ]", ANSI_GREEN + ANSI_BOLD)
            sev_badge = color_text(f"{sev:^10}", ANSI_BLUE)
        elif st_lower in ("inconclusive", "warning"):
            warn_count += 1
            badge = color_text(f"[ {status.upper():^8} ]", ANSI_YELLOW + ANSI_BOLD)
            sev_badge = color_text(f"{sev:^10}", ANSI_YELLOW + ANSI_BOLD)
        else:
            fail_count += 1
            badge = color_text(f"[ {status.upper():^8} ]", ANSI_RED + ANSI_BOLD)
            sev_badge = color_text(f"{sev:^10}", ANSI_RED + ANSI_BOLD)

        det = details if len(details) <= 46 else details[:43] + "..."
        lines.append(f"│ {ctrl:<27} │ {pad_ansi(badge, 14)} │ {pad_ansi(sev_badge, 10)} │ {det:<46} │")

    # 1. Redirect
    red = obs.get("redirect", {})
    add_row("HTTP -> HTTPS Redirect", red.get("status", "unknown"), "INFO" if red.get("status") == "pass" else "MEDIUM", red.get("details", ""))

    # 2. TLS
    tls = obs.get("tls", {})
    add_row("TLS Certificate Validity", tls.get("status", "unknown"), "INFO" if tls.get("status") == "pass" else "HIGH", tls.get("details", ""))

    # 3. Headers
    hdrs = obs.get("headers", {})
    for h, (label, def_sev) in [
        ("Strict-Transport-Security", ("Strict-Transport-Security", "MEDIUM")),
        ("Content-Security-Policy", ("Content-Security-Policy", "MEDIUM")),
        ("X-Content-Type-Options", ("X-Content-Type-Options", "LOW")),
        ("Referrer-Policy", ("Referrer-Policy", "LOW")),
    ]:
        h_data = hdrs.get(h, {})
        st = h_data.get("status", "unknown")
        val = h_data.get("value") or h_data.get("error") or "Missing / Not Configured"
        add_row(label, st, "INFO" if st == "present" else def_sev, val)

    lines.append("└" + "─" * 29 + "┴" + "─" * 16 + "┴" + "─" * 12 + "┴" + "─" * 48 + "┘")
    lines.append(f" Summary: {color_text(f'{pass_count} Passed', ANSI_GREEN)}, {color_text(f'{warn_count} Inconclusive', ANSI_YELLOW)}, {color_text(f'{fail_count} Failed', ANSI_RED if fail_count > 0 else ANSI_GREEN)}")
    return "\n".join(lines)


def format_compare_table(diff: dict) -> str:
    """Format drift comparison result as a Trivy-style Unicode box table."""
    if diff.get("type") == "host" or diff.get("baseline", {}).get("type") == "host":
        return format_host_compare_table(diff)

    lines = []
    target = diff["target"]
    base_saved = diff["baseline"].get("saved_at", "Unknown")
    lines.append(color_text(BANNER.strip(), ANSI_CYAN))
    lines.append("")
    lines.append(f" Target: {color_text(target, ANSI_BOLD)}")
    lines.append(f" Baseline Saved: {base_saved}  |  Current Time: {diff['live'].get('timestamp')}")
    lines.append("")

    lines.append("┌" + "─" * 29 + "┬" + "─" * 12 + "┬" + "─" * 12 + "┬" + "─" * 12 + "┬" + "─" * 10 + "┐")
    lines.append(f"│ {'CONTROL':<27} │ {'BASELINE':<10} │ {'CURRENT':<10} │ {'STATUS':<10} │ {'SEVERITY':<8} │")
    lines.append("├" + "─" * 29 + "┼" + "─" * 12 + "┼" + "─" * 12 + "┼" + "─" * 12 + "┼" + "─" * 10 + "┤")

    reg_map = {r["control"]: r for r in diff["regressions"]}

    controls_to_show = [
        ("HTTP->HTTPS Redirect", diff["baseline"].get("redirect", {}).get("status"), diff["live"].get("redirect", {}).get("status")),
        ("TLS Certificate Validity", diff["baseline"].get("tls", {}).get("status"), diff["live"].get("tls", {}).get("status")),
    ]

    for h in ("Strict-Transport-Security", "Content-Security-Policy", "X-Content-Type-Options", "Referrer-Policy"):
        b_st = diff["baseline"].get("headers", {}).get(h, {}).get("status")
        l_st = diff["live"].get("headers", {}).get(h, {}).get("status")
        controls_to_show.append((h, b_st, l_st))

    for ctrl, b_st, l_st in controls_to_show:
        if ctrl in reg_map:
            reg = reg_map[ctrl]
            st_text = pad_ansi(color_text("DRIFT", ANSI_RED + ANSI_BOLD), 10)
            sev_text = pad_ansi(severity_badge(reg["severity"]), 8)
        else:
            st_text = pad_ansi(color_text("MATCH", ANSI_GREEN), 10)
            sev_text = pad_ansi("-", 8)
        lines.append(f"│ {ctrl:<27} │ {str(b_st):<10} │ {str(l_st):<10} │ {st_text} │ {sev_text} │")

    lines.append("└" + "─" * 29 + "┴" + "─" * 12 + "┴" + "─" * 12 + "┴" + "─" * 12 + "┴" + "─" * 10 + "┘")

    if diff["drift_detected"]:
        lines.append(
            color_text(
                f"\n⚠ DRIFT DETECTED: {diff['regressions_count']} security regression(s) identified!",
                ANSI_RED + ANSI_BOLD,
            )
        )
        lines.append("\nRecommended Actions:")
        for idx, r in enumerate(diff["regressions"], 1):
            lines.append(
                f"  {idx}. [{r['severity'].upper()}] {r['control']}: {r['recommendation']}"
            )
    else:
        lines.append(
            color_text(
                "\n✔ No security drift detected. All controls match or exceed baseline.",
                ANSI_GREEN + ANSI_BOLD,
            )
        )

    return "\n".join(lines)


# Swytchcode Issue Notification
def generate_issue_content(target_url: str, diff: dict) -> tuple[str, str]:
    """
    Format GitHub Issue title and markdown body for security regressions.
    """
    if diff.get("type") == "host" or is_local_target(target_url):
        return generate_host_issue_content(diff)

    hostname = urllib.parse.urlparse(target_url).hostname or target_url
    regressions = diff["regressions"]
    title = f"[NETRA Security Drift] {hostname}: {len(regressions)} regression(s) detected"

    timestamp = diff["live"].get("timestamp")
    baseline_saved = diff["baseline"].get("saved_at")

    body_lines = [
        f"## NETRA Security Drift Alert",
        f"",
        f"**Target Host:** `{target_url}`  ",
        f"**Detected At:** `{timestamp}`  ",
        f"**Baseline Anchor:** `{baseline_saved}`  ",
        f"**Total Regressions:** `{len(regressions)}`  ",
        f"",
        f"### Security Regressions Summary",
        f"",
        f"| Control | Severity | Baseline | Current | Recommendation |",
        f"|---|---|---|---|---|",
    ]

    for r in regressions:
        body_lines.append(
            f"| **{r['control']}** | `{r['severity'].upper()}` | `{r['baseline']}` | `{r['observed']}` | {r['recommendation']} |"
        )

    body_lines.extend(
        [
            f"",
            f"### Action Required",
            f"Security controls that were previously configured and verified have degraded. Review the recommendations above and update the web server configuration.",
            f"",
            f"---",
            f"*Dispatched automatically by [NETRA_CLI](https://github.com/avinash/netra-cli) via Swytchcode Execution Authority Kernel.*",
        ]
    )

    return title, "\n".join(body_lines)


def dispatch_swytchcode_issue(owner: str, repo: str, title: str, body: str) -> int:
    """
    Dispatch issue creation to Swytchcode execution kernel via JSON stdin.
    """
    payload = {
        "tool": "github.issue.create",
        "args": {
            "owner": owner,
            "repo": repo,
            "body": {
                "title": title,
                "body": body,
            },
        },
    }

    try:
        proc = subprocess.run(
            ["swytchcode", "exec"],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
        )
    except FileNotFoundError:
        sys.stderr.write(
            "Error: 'swytchcode' binary not found in PATH. Ensure Swytchcode CLI is installed.\n"
        )
        return 127

    if proc.returncode == 0:
        print(
            color_text("✔ Issue created successfully via Swytchcode!", ANSI_GREEN + ANSI_BOLD)
        )
        if proc.stdout:
            try:
                data = json.loads(proc.stdout)
                if isinstance(data, dict) and "html_url" in data:
                    print(f"Issue URL: {data['html_url']}")
                elif isinstance(data, dict) and "id" in data:
                    print(f"Issue ID: {data['id']}")
            except json.JSONDecodeError:
                print(proc.stdout)
        return 0
    else:
        sys.stderr.write(
            f"Swytchcode execution failed with exit code {proc.returncode}:\n"
        )
        # Parse structured error from stderr or stdout
        combined_err = (proc.stderr or "") + "\n" + (proc.stdout or "")
        parsed_err = None
        for line in combined_err.splitlines():
            line_s = line.strip()
            if line_s.startswith("{") and line_s.endswith("}"):
                try:
                    obj = json.loads(line_s)
                    if isinstance(obj, dict) and "error" in obj:
                        parsed_err = obj
                        break
                except json.JSONDecodeError:
                    pass

        if parsed_err:
            sys.stderr.write(f"Error: {parsed_err.get('error')}\n")
            if "suggested_action" in parsed_err:
                sys.stderr.write(f"Suggested Action: {parsed_err.get('suggested_action')}\n")
            if "reference_id" in parsed_err:
                sys.stderr.write(f"Reference ID: {parsed_err.get('reference_id')}\n")
        else:
            err_msg = proc.stderr.strip() or proc.stdout.strip()
            sys.stderr.write(f"{err_msg}\n")
        return proc.returncode


# CLI Subcommand Handlers
def handle_check(args) -> int:
    """Handle 'netra check' subcommand."""
    target = getattr(args, "target", None) or "localhost"
    if is_local_target(target):
        obs = inspect_local_host()
        if args.json:
            print(json.dumps(obs, indent=2))
        else:
            print(format_host_observation_table(obs))
        return 0

    try:
        validated = validate_url(target)
        obs = observe(validated, timeout=args.timeout)
    except ValueError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 2

    if args.json:
        print(json.dumps(obs, indent=2))
    else:
        print(format_observation_table(obs))
    return 0


def handle_baseline_save(args) -> int:
    """Handle 'netra baseline save' subcommand."""
    target = getattr(args, "target", None) or "localhost"
    if is_local_target(target):
        obs = inspect_local_host()
        filepath = get_baseline_filepath("localhost")
        success = save_baseline(obs, filepath=filepath, auto_confirm=args.yes)
        return 0 if success else 1

    try:
        validated = validate_url(target)
        obs = observe(validated, timeout=args.timeout)
    except ValueError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 2

    filepath = get_baseline_filepath(validated)
    success = save_baseline(obs, filepath=filepath, auto_confirm=args.yes)
    return 0 if success else 1


def handle_compare(args) -> int:
    """Handle 'netra compare' subcommand."""
    target = getattr(args, "target", None) or "localhost"
    if is_local_target(target):
        filepath = get_baseline_filepath("localhost")
        try:
            baseline = load_baseline(filepath)
        except FileNotFoundError as e:
            sys.stderr.write(f"Error: {e}\n")
            return 2

        obs = inspect_local_host()
        diff = compare_drift(baseline, obs)

        if args.json:
            print(json.dumps(diff, indent=2))
        else:
            print(format_compare_table(diff))
        return 1 if diff["drift_detected"] else 0

    try:
        validated = validate_url(target)
    except ValueError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 2

    filepath = get_baseline_filepath(validated)
    try:
        baseline = load_baseline(filepath)
    except FileNotFoundError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 2

    obs = observe(validated, timeout=args.timeout)
    diff = compare_drift(baseline, obs)

    if args.json:
        print(json.dumps(diff, indent=2))
    else:
        print(format_compare_table(diff))

    return 1 if diff["drift_detected"] else 0


def handle_notify(args) -> int:
    """Handle 'netra notify' subcommand."""
    target = getattr(args, "target", None) or "localhost"
    try:
        owner, repo = validate_repo(args.repo)
    except ValueError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 2

    if is_local_target(target):
        filepath = get_baseline_filepath("localhost")
        try:
            baseline = load_baseline(filepath)
        except FileNotFoundError as e:
            sys.stderr.write(f"Error: {e}\n")
            return 2

        obs = inspect_local_host()
        diff = compare_drift(baseline, obs)

        if not diff["drift_detected"]:
            print("No security drift detected for localhost. No issue notification needed.")
            return 0

        title, body = generate_issue_content("localhost", diff)
    else:
        try:
            validated = validate_url(target)
        except ValueError as e:
            sys.stderr.write(f"Error: {e}\n")
            return 2

        filepath = get_baseline_filepath(validated)
        try:
            baseline = load_baseline(filepath)
        except FileNotFoundError as e:
            sys.stderr.write(f"Error: {e}\n")
            return 2

        obs = observe(validated, timeout=args.timeout)
        diff = compare_drift(baseline, obs)

        if not diff["drift_detected"]:
            print(f"No security drift detected for {validated}. No issue notification needed.")
            return 0

        title, body = generate_issue_content(validated, diff)

    if not args.confirm:
        print("=" * 80)
        print(color_text("[PREVIEW MODE] GitHub Issue Preview", ANSI_YELLOW + ANSI_BOLD))
        print(f"Target Repository: {owner}/{repo}")
        print("=" * 80)
        print(f"Title: {title}\n")
        print("Body:")
        print(body)
        print("=" * 80)
        print(
            color_text(
                "Run with --confirm to dispatch this issue to GitHub via Swytchcode:\n"
                f"  netra notify --target {target} --repo {owner}/{repo} --confirm",
                ANSI_CYAN,
            )
        )
        return 0

    return dispatch_swytchcode_issue(owner, repo, title, body)


def run_top_dashboard(target: str, interval: float = 5.0, timeout: float = 10.0) -> int:
    """
    Launch interactive btop-style curses terminal monitoring dashboard.
    Zero external dependencies, uses standard library curses.
    """
    if is_local_target(target):
        return run_host_top_dashboard(interval=interval)

    if not sys.stdin.isatty():
        sys.stderr.write("Error: 'top' dashboard requires an interactive terminal (TTY).\n")
        return 1

    try:
        import curses
    except ImportError:
        sys.stderr.write(
            "Error: 'curses' module not available. "
            "Built-in on Linux/macOS. On Windows, install 'windows-curses'.\n"
        )
        return 1

    def curses_main(stdscr):
        try:
            curses.curs_set(0)
        except curses.error:
            pass

        stdscr.nodelay(True)
        stdscr.timeout(500)
        if curses.has_colors():
            curses.start_color()
            try:
                curses.use_default_colors()
            except curses.error:
                pass
            curses.init_pair(1, curses.COLOR_GREEN, -1)
            curses.init_pair(2, curses.COLOR_RED, -1)
            curses.init_pair(3, curses.COLOR_YELLOW, -1)
            curses.init_pair(4, curses.COLOR_CYAN, -1)
            curses.init_pair(5, curses.COLOR_BLUE, -1)

            col_pass = curses.color_pair(1) | curses.A_BOLD
            col_fail = curses.color_pair(2) | curses.A_BOLD
            col_warn = curses.color_pair(3) | curses.A_BOLD
            col_cyan = curses.color_pair(4) | curses.A_BOLD
            col_blue = curses.color_pair(5)
        else:
            col_pass = curses.A_BOLD
            col_fail = curses.A_BOLD
            col_warn = curses.A_NORMAL
            col_cyan = curses.A_BOLD
            col_blue = curses.A_NORMAL

        last_poll = 0.0
        obs = None
        latency_ms = 0
        diff = None
        status_msg = f"Live monitoring active (Refresh every {interval:.1f}s) | Press 'q' to quit"
        status_msg_time = time.time()

        while True:
            now = time.time()
            if obs is None or (now - last_poll >= interval):
                last_poll = now
                t0 = time.time()
                try:
                    obs = observe(target, timeout=timeout)
                    latency_ms = int((time.time() - t0) * 1000)

                    filepath = get_baseline_filepath(target)
                    if filepath.exists():
                        try:
                            baseline = load_baseline(filepath)
                            diff = compare_drift(baseline, obs)
                        except Exception:
                            diff = None
                    else:
                        diff = None
                except Exception as e:
                    obs = {
                        "error": str(e),
                        "target": target,
                        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    }
                    diff = None

            max_y, max_x = stdscr.getmaxyx()
            stdscr.erase()

            if max_y < 22 or max_x < 76:
                msg = f"Terminal size too small ({max_x}x{max_y}). Expand window to at least 76x22."
                try:
                    stdscr.addstr(0, 0, msg[:max_x - 1], col_warn)
                except curses.error:
                    pass
            else:
                def draw(y, x, text, attr=0):
                    if 0 <= y < max_y and 0 <= x < max_x:
                        avail = max_x - 1 - x
                        if avail > 0:
                            try:
                                stdscr.addstr(y, x, text[:avail], attr)
                            except curses.error:
                                pass

                # Draw top border
                draw(0, 0, "┌" + "─" * (max_x - 2) + "┐")
                title_bar = f" NETRA LIVE MONITOR  ──  [Target: {target}] "
                draw(0, 4, title_bar, col_cyan)

                # Row 2: Target info & Score
                if "error" in obs:
                    draw(2, 2, f"Error inspecting target: {obs['error']}", col_fail)
                else:
                    score, grade, bar = calculate_security_score(obs)
                    grade_color = col_pass if grade in ("A+", "A") else (col_cyan if grade == "B" else (col_warn if grade == "C" else col_fail))
                    draw(2, 2, f"Security Score: [{bar}] {score}/100", curses.A_BOLD)
                    draw(2, 44, f"GRADE: {grade}", grade_color)
                    draw(2, 58, f"Latency: {latency_ms}ms", col_blue)
                    ts_str = obs.get("timestamp", "")
                    time_part = ts_str[11:19] if len(ts_str) >= 19 else ts_str
                    draw(2, max_x - 22, f"Audit: {time_part} UTC")

                # Section divider
                draw(3, 0, "├" + "─" * (max_x - 2) + "┤")

                # TLS Certificate panel
                draw(4, 2, "TLS CERTIFICATE EXPIRATION GAUGE", col_cyan)
                tls = obs.get("tls", {}) if "error" not in obs else {}
                days = tls.get("days_left")
                exp_date = tls.get("not_after", "Unknown")
                if days is not None:
                    gauge_len = 36
                    ratio = min(max(days, 0), 365) / 365.0
                    filled = int(round(ratio * gauge_len))
                    g_bar = "█" * filled + "░" * (gauge_len - filled)
                    g_col = col_pass if days > 30 else (col_warn if days > 14 else col_fail)
                    draw(5, 2, f"[{g_bar}] {days} Days Remaining", g_col)
                    issuer_str = str(tls.get("issuer", "Unknown"))
                    draw(6, 2, f"Expires: {exp_date}  |  Issuer: {issuer_str[:35]}")
                else:
                    draw(5, 2, f"TLS Status: {tls.get('status', 'unknown').upper()} - {tls.get('details', '')}", col_warn)

                # Section divider
                draw(7, 0, "├" + "─" * (max_x - 2) + "┤")

                # Perimeter Controls Matrix
                draw(8, 2, "PERIMETER CONTROLS MATRIX", col_cyan)

                red = obs.get("redirect", {}) if "error" not in obs else {}
                red_st = red.get("status", "unknown")
                red_col = col_pass if red_st == "pass" else (col_warn if red_st == "inconclusive" else col_fail)
                draw(10, 4, f"{'HTTP -> HTTPS Redirect:':<25}")
                draw(10, 30, f"[{red_st.upper():^8}]", red_col)
                draw(10, 42, str(red.get("details", ""))[:max_x - 44])

                hdrs = obs.get("headers", {}) if "error" not in obs else {}
                controls = [
                    ("Strict-Transport-Security", "HSTS Protection:"),
                    ("Content-Security-Policy", "CSP Hardening:"),
                    ("X-Content-Type-Options", "nosniff Guard:"),
                    ("Referrer-Policy", "Referrer Policy:"),
                ]

                row_idx = 11
                for h_name, label in controls:
                    h_data = hdrs.get(h_name, {})
                    st = h_data.get("status", "unknown")
                    st_col = col_pass if st == "present" else (col_warn if st == "inconclusive" else col_fail)
                    val = h_data.get("value") or h_data.get("error") or "Missing / Not Configured"
                    draw(row_idx, 4, f"{label:<25}")
                    draw(row_idx, 30, f"[{st.upper():^8}]", st_col)
                    draw(row_idx, 42, str(val)[:max_x - 44])
                    row_idx += 1

                # Section divider
                draw(16, 0, "├" + "─" * (max_x - 2) + "┤")

                # Baseline status panel
                draw(17, 2, "BASELINE DRIFT CONTRACT", col_cyan)
                if diff is None:
                    draw(18, 4, "No baseline locked yet. (Press 's' to lock current posture as baseline)", col_warn)
                else:
                    saved_at = diff["baseline"].get("saved_at", "")[:19]
                    if diff.get("drift_detected"):
                        reg_cnt = len(diff.get("regressions", []))
                        draw(18, 4, f"▲ DRIFT DETECTED: {reg_cnt} regression(s) vs baseline saved {saved_at}", col_fail)
                    else:
                        draw(18, 4, f"✔ BASELINE MATCH: Healthy contract (saved {saved_at})", col_pass)

                # Hotkeys & status bar
                draw(max_y - 3, 0, "├" + "─" * (max_x - 2) + "┤")
                hotkeys = "HOTKEYS: [r] Refresh Now   [s] Save Baseline Snapshot   [q] Quit"
                draw(max_y - 2, 2, hotkeys, curses.A_BOLD)

                # Flash message (fade after 4s)
                if time.time() - status_msg_time > 4.0:
                    status_msg = f"Live monitoring active (interval: {interval:.1f}s) | Press 'q' to quit"
                draw(max_y - 1, 2, status_msg, col_cyan)

                # Outer bottom border
                draw(max_y - 1, 0, "└")
                draw(max_y - 1, max_x - 1, "┘")

            stdscr.refresh()

            # Handle user input
            try:
                ch = stdscr.getch()
            except curses.error:
                ch = -1

            if ch in (ord('q'), ord('Q'), 27):
                break
            elif ch in (ord('r'), ord('R')):
                status_msg = "Refreshing security posture now..."
                status_msg_time = time.time()
                obs = None
            elif ch in (ord('s'), ord('S')):
                if obs and "error" not in obs:
                    filepath = get_baseline_filepath(target)
                    save_baseline(obs, filepath=filepath, auto_confirm=True)
                    try:
                        baseline = load_baseline(filepath)
                        diff = compare_drift(baseline, obs)
                    except Exception:
                        pass
                    status_msg = f"✔ Baseline snapshot saved to {filepath.name}!"
                    status_msg_time = time.time()

        return 0

    try:
        curses.wrapper(curses_main)
    except KeyboardInterrupt:
        pass
    return 0


def handle_top(args) -> int:
    """Handle 'netra top' / 'netra monitor' subcommand."""
    target = getattr(args, "target", None) or "localhost"
    if not is_local_target(target):
        try:
            target = validate_url(target)
        except ValueError as e:
            sys.stderr.write(f"Error: {e}\n")
            return 2

    return run_top_dashboard(target, interval=args.interval, timeout=args.timeout)


class NetraArgumentParser(argparse.ArgumentParser):
    """Custom parser providing nmap-style bare domain invocation and positional targets."""

    def parse_args(self, args=None, namespace=None):
        if args is None:
            args = sys.argv[1:]
        else:
            args = list(args)

        known_subcommands = {"check", "baseline", "compare", "notify", "top", "monitor"}
        help_version_flags = {"-h", "--help", "--version", "-v"}

        # Nmap-style ergonomics: if invoked on root parser without a known subcommand,
        # route automatically to 'check' (e.g. `netra example.com` or `netra example.com --json`),
        # unless user requested root-level help/version with no other arguments.
        if self.prog == "netra":
            is_pure_root_help = bool(args) and set(args).issubset(help_version_flags)
            if not args:
                args = ["check"]
            elif not is_pure_root_help and not any(a in known_subcommands for a in args):
                args = ["check"] + args

        ns = super().parse_args(args, namespace)

        # Consolidate positional target with --target flag, defaulting to "localhost" if absent
        if hasattr(ns, "target_pos"):
            if getattr(ns, "target", None) is None:
                ns.target = ns.target_pos
            if not getattr(ns, "target", None):
                ns.target = "localhost"

        return ns


# Argument Parser
def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser."""
    parser = NetraArgumentParser(
        prog="netra",
        description="NETRA_CLI: Developer Laptop & Workspace Threat Guardian + Remote Perimeter Scanner",
    )
    parser.add_argument(
        "-v", "--version", action="version", version=f"NETRA_CLI v{VERSION}"
    )

    subparsers = parser.add_subparsers(
        dest="command", required=True
    )

    # 1. check
    check_p = subparsers.add_parser(
        "check", help="Inspect security posture (defaults to local laptop host; or specify target URL)"
    )
    check_p.add_argument(
        "target_pos",
        nargs="?",
        default=None,
        metavar="target",
        help="Target URL or localhost (default: localhost)",
    )
    check_p.add_argument(
        "--target", default=None, help="Target URL or localhost (default: localhost)"
    )
    check_p.add_argument(
        "--json", action="store_true", help="Output observation in raw JSON"
    )
    check_p.add_argument(
        "--timeout", type=float, default=10.0, help="Network timeout in seconds (default: 10.0)"
    )

    # 2. baseline
    baseline_p = subparsers.add_parser("baseline", help="Manage security baselines")
    baseline_sub = baseline_p.add_subparsers(
        dest="baseline_action", required=True
    )
    base_save_p = baseline_sub.add_parser(
        "save", help="Save current observation as reviewed baseline (defaults to localhost)"
    )
    base_save_p.add_argument(
        "target_pos",
        nargs="?",
        default=None,
        metavar="target",
        help="Target URL or localhost (default: localhost)",
    )
    base_save_p.add_argument(
        "--target", default=None, help="Target URL or localhost (default: localhost)"
    )
    base_save_p.add_argument(
        "--yes", action="store_true", help="Auto-confirm save without interactive prompt"
    )
    base_save_p.add_argument(
        "--timeout", type=float, default=10.0, help="Network timeout in seconds (default: 10.0)"
    )

    # 3. compare
    comp_p = subparsers.add_parser(
        "compare", help="Compare live security posture against saved baseline (defaults to localhost)"
    )
    comp_p.add_argument(
        "target_pos",
        nargs="?",
        default=None,
        metavar="target",
        help="Target URL or localhost (default: localhost)",
    )
    comp_p.add_argument(
        "--target", default=None, help="Target URL or localhost (default: localhost)"
    )
    comp_p.add_argument(
        "--json", action="store_true", help="Output drift comparison in raw JSON"
    )
    comp_p.add_argument(
        "--timeout", type=float, default=10.0, help="Network timeout in seconds (default: 10.0)"
    )

    # 4. notify
    notif_p = subparsers.add_parser(
        "notify", help="Generate or dispatch GitHub issue alert for detected drift (defaults to localhost)"
    )
    notif_p.add_argument(
        "target_pos",
        nargs="?",
        default=None,
        metavar="target",
        help="Target URL or localhost (default: localhost)",
    )
    notif_p.add_argument(
        "--target", default=None, help="Target URL or localhost (default: localhost)"
    )
    notif_p.add_argument(
        "--repo", required=True, help="GitHub repository in OWNER/REPO format"
    )
    notif_p.add_argument(
        "--confirm",
        action="store_true",
        help="Confirm dispatch to GitHub via Swytchcode (omitting prints preview)",
    )
    notif_p.add_argument(
        "--timeout", type=float, default=10.0, help="Network timeout in seconds (default: 10.0)"
    )

    # 5. top / monitor
    top_p = subparsers.add_parser(
        "top", aliases=["monitor"], help="Launch interactive live terminal monitoring dashboard (btop-style radar)"
    )
    top_p.add_argument(
        "target_pos",
        nargs="?",
        default=None,
        metavar="target",
        help="Target URL or localhost (default: localhost)",
    )
    top_p.add_argument(
        "--target", default=None, help="Target URL or localhost (default: localhost)"
    )
    top_p.add_argument(
        "--interval", type=float, default=5.0, help="Polling refresh interval in seconds (default: 5.0)"
    )
    top_p.add_argument(
        "--timeout", type=float, default=10.0, help="Network timeout in seconds (default: 10.0)"
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "check":
        return handle_check(args)
    elif args.command == "baseline":
        if args.baseline_action == "save":
            return handle_baseline_save(args)
    elif args.command == "compare":
        return handle_compare(args)
    elif args.command == "notify":
        return handle_notify(args)
    elif args.command in ("top", "monitor"):
        return handle_top(args)

    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())

