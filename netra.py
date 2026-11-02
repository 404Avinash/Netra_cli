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
    Validate target URL format.
    Must contain scheme (http or https) and a valid netloc/hostname.
    """
    if not url_str or not isinstance(url_str, str):
        raise ValueError("Target URL cannot be empty.")

    parsed = urllib.parse.urlparse(url_str.strip())
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(
            f"Invalid URL scheme '{parsed.scheme}'. Target must start with http:// or https://"
        )
    if not parsed.netloc or not parsed.hostname:
        raise ValueError(f"Invalid target URL '{url_str}'. Must include a valid hostname.")

    return url_str.strip()


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
    """Generate deterministic baseline file path for a target URL."""
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
    target = observation["target"]
    if filepath is None:
        filepath = get_baseline_filepath(target)

    if not auto_confirm:
        confirm_prompt = input(f"Save baseline for '{target}' to {filepath}? [y/N]: ").strip()
        if confirm_prompt.lower() not in ("y", "yes"):
            print("Baseline save aborted by user.")
            return False

    filepath.parent.mkdir(parents=True, exist_ok=True)
    baseline_payload = {
        "target": target,
        "saved_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "reviewed": True,
        "redirect": observation["redirect"],
        "tls": observation["tls"],
        "headers": observation["headers"],
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
        raise FileNotFoundError(
            f"Baseline file not found at '{filepath}'. Run 'netra baseline save --target URL' first."
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
    try:
        obs = observe(args.target, timeout=args.timeout)
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
    try:
        obs = observe(args.target, timeout=args.timeout)
    except ValueError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 2

    filepath = get_baseline_filepath(args.target)
    success = save_baseline(obs, filepath=filepath, auto_confirm=args.yes)
    return 0 if success else 1


def handle_compare(args) -> int:
    """Handle 'netra compare' subcommand."""
    try:
        target = validate_url(args.target)
    except ValueError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 2

    filepath = get_baseline_filepath(target)
    try:
        baseline = load_baseline(filepath)
    except FileNotFoundError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 2

    obs = observe(target, timeout=args.timeout)
    diff = compare_drift(baseline, obs)

    if args.json:
        print(json.dumps(diff, indent=2))
    else:
        print(format_compare_table(diff))

    return 1 if diff["drift_detected"] else 0


def handle_notify(args) -> int:
    """Handle 'netra notify' subcommand."""
    try:
        target = validate_url(args.target)
        owner, repo = validate_repo(args.repo)
    except ValueError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 2

    filepath = get_baseline_filepath(target)
    try:
        baseline = load_baseline(filepath)
    except FileNotFoundError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 2

    obs = observe(target, timeout=args.timeout)
    diff = compare_drift(baseline, obs)

    if not diff["drift_detected"]:
        print(f"No security drift detected for {target}. No issue notification needed.")
        return 0

    title, body = generate_issue_content(target, diff)

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
    try:
        target = validate_url(args.target)
    except ValueError as e:
        sys.stderr.write(f"Error: {e}\n")
        return 2

    return run_top_dashboard(target, interval=args.interval, timeout=args.timeout)


# Argument Parser
def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="netra",
        description="NETRA_CLI: Network & Endpoint Threat and Resilience Assessor CLI",
    )
    parser.add_argument(
        "--version", action="version", version=f"NETRA_CLI v{VERSION}"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. check
    check_p = subparsers.add_parser(
        "check", help="Inspect a target URL's security posture (redirect, TLS, headers)"
    )
    check_p.add_argument(
        "--target", required=True, help="Target URL (e.g. https://example.com)"
    )
    check_p.add_argument(
        "--json", action="store_true", help="Output observation in raw JSON"
    )
    check_p.add_argument(
        "--timeout", type=float, default=10.0, help="Network timeout in seconds (default: 10.0)"
    )

    # 2. baseline
    baseline_p = subparsers.add_parser("baseline", help="Manage security baselines")
    baseline_sub = baseline_p.add_subparsers(dest="baseline_action", required=True)
    base_save_p = baseline_sub.add_parser("save", help="Save current observation as reviewed baseline")
    base_save_p.add_argument(
        "--target", required=True, help="Target URL (e.g. https://example.com)"
    )
    base_save_p.add_argument(
        "--yes", action="store_true", help="Auto-confirm save without interactive prompt"
    )
    base_save_p.add_argument(
        "--timeout", type=float, default=10.0, help="Network timeout in seconds (default: 10.0)"
    )

    # 3. compare
    comp_p = subparsers.add_parser(
        "compare", help="Compare target URL live security posture against saved baseline"
    )
    comp_p.add_argument(
        "--target", required=True, help="Target URL (e.g. https://example.com)"
    )
    comp_p.add_argument(
        "--json", action="store_true", help="Output drift comparison in raw JSON"
    )
    comp_p.add_argument(
        "--timeout", type=float, default=10.0, help="Network timeout in seconds (default: 10.0)"
    )

    # 4. notify
    notif_p = subparsers.add_parser(
        "notify", help="Generate or dispatch GitHub issue alert for detected drift"
    )
    notif_p.add_argument(
        "--target", required=True, help="Target URL (e.g. https://example.com)"
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
        "top", aliases=["monitor"], help="Launch interactive live terminal monitoring dashboard (btop-style)"
    )
    top_p.add_argument(
        "--target", required=True, help="Target URL (e.g. https://example.com)"
    )
    top_p.add_argument(
        "--interval", type=float, default=5.0, help="Polling refresh interval in seconds (default: 5.0)"
    )
    top_p.add_argument(
        "--timeout", type=float, default=10.0, help="Network timeout in seconds (default: 10.0)"
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

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
