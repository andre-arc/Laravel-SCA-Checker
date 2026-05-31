#!/usr/bin/env python3
"""
Laravel Supply Chain Attack Checker
Inspects composer.lock and vendor/ for indicators of compromise
without booting PHP or executing any project code.
"""

import json
import os
import re
import sys
import subprocess
import argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

# ── Known compromised packages ────────────────────────────────────────────────
KNOWN_COMPROMISED: dict[str, dict] = {
    "laravel-lang/lang": {
        "window": ("2026-05-22", "2026-05-23"),
        "description": "Credential stealer via autoload.files (tag rewrite attack)",
        "ref": "https://snyk.io/blog/laravel-lang-supply-chain-advisory/",
    },
    "laravel-lang/http-statuses": {
        "window": ("2026-05-22", "2026-05-23"),
        "description": "Credential stealer via autoload.files (tag rewrite attack)",
        "ref": "https://snyk.io/blog/laravel-lang-supply-chain-advisory/",
    },
    "laravel-lang/attributes": {
        "window": ("2026-05-22", "2026-05-23"),
        "description": "Credential stealer via autoload.files (tag rewrite attack)",
        "ref": "https://snyk.io/blog/laravel-lang-supply-chain-advisory/",
    },
    "laravel-lang/actions": {
        "window": ("2026-05-22", "2026-05-23"),
        "description": "Credential stealer via autoload.files (tag rewrite attack)",
        "ref": "https://snyk.io/blog/laravel-lang-supply-chain-advisory/",
    },
}

# ── Known C2 / exfiltration domains ──────────────────────────────────────────
KNOWN_C2_DOMAINS = [
    "flipboxstudio.info",
    "flipboxstudio[.]info",
]

# ── Malicious code patterns (regex) ──────────────────────────────────────────
MALICIOUS_PATTERNS = [
    (r"eval\s*\(\s*base64_decode",          "eval(base64_decode(...)) — obfuscated code execution"),
    (r"base64_decode\s*\(.*\$[a-z_]+\s*\)", "base64_decode with variable — possible payload decoder"),
    (r"file_get_contents\s*\(\s*['\"]https?://", "file_get_contents from remote URL"),
    (r"curl_exec\s*\(",                      "curl_exec — possible data exfiltration"),
    (r"fsockopen\s*\(",                      "fsockopen — raw socket connection"),
    (r"shell_exec\s*\(",                     "shell_exec — OS command execution"),
    (r"passthru\s*\(",                       "passthru — OS command execution"),
    (r"proc_open\s*\(",                      "proc_open — OS command execution"),
    (r"system\s*\(\s*\$",                   "system() with variable argument"),
    (r"flipboxstudio",                       "Known C2 domain (laravel-lang attack)"),
    (r"/payload",                            "Suspicious '/payload' URL path"),
    (r"/exfil",                              "Suspicious '/exfil' URL path"),
    (r"\.laravel_locale",                    "Known malware temp directory marker"),
]

# ── Breach windows (start, end) ───────────────────────────────────────────────
BREACH_WINDOWS = [
    ("2026-05-22", "2026-05-23", "laravel-lang tag rewrite attack"),
]

# ── ANSI colors ───────────────────────────────────────────────────────────────
# Disabled automatically when output is not a TTY (e.g. piped, Windows CMD)
_USE_COLOR = sys.stdout.isatty()

RED    = "\033[91m" if _USE_COLOR else ""
YELLOW = "\033[93m" if _USE_COLOR else ""
GREEN  = "\033[92m" if _USE_COLOR else ""
CYAN   = "\033[96m" if _USE_COLOR else ""
BOLD   = "\033[1m"  if _USE_COLOR else ""
RESET  = "\033[0m"  if _USE_COLOR else ""

def red(s):    return f"{RED}{s}{RESET}"
def yellow(s): return f"{YELLOW}{s}{RESET}"
def green(s):  return f"{GREEN}{s}{RESET}"
def cyan(s):   return f"{CYAN}{s}{RESET}"
def bold(s):   return f"{BOLD}{s}{RESET}"


@dataclass
class Finding:
    severity: str   # CRITICAL / HIGH / MEDIUM / LOW / INFO
    category: str
    package: Optional[str]
    file: Optional[str]
    line: Optional[int]
    message: str
    detail: str = ""
    ref: str = ""


def severity_color(s: str) -> str:
    return {
        "CRITICAL": red(bold(s)),
        "HIGH":     red(s),
        "MEDIUM":   yellow(s),
        "LOW":      cyan(s),
        "INFO":     green(s),
    }.get(s, s)


def print_banner():
    print(bold("""
╔══════════════════════════════════════════════════════╗
║      Laravel Supply Chain Attack Checker             ║
║      Inspects without executing any PHP code         ║
╚══════════════════════════════════════════════════════╝"""))


def load_lock(project_path: Path) -> Optional[dict]:
    lock_file = project_path / "composer.lock"
    if not lock_file.exists():
        print(red(f"  [!] composer.lock not found at {lock_file}"))
        return None
    with open(lock_file) as f:
        return json.load(f)


def check_known_compromised(lock: dict) -> list[Finding]:
    findings = []
    all_pkgs = lock.get("packages", []) + lock.get("packages-dev", [])
    for pkg in all_pkgs:
        name = pkg.get("name", "")
        if name in KNOWN_COMPROMISED:
            info = KNOWN_COMPROMISED[name]
            t = pkg.get("time", "")[:10]
            w_start, w_end = info["window"]
            in_window = w_start <= t <= w_end if t else False
            findings.append(Finding(
                severity="CRITICAL",
                category="known_compromise",
                package=name,
                file="composer.lock",
                line=None,
                message=f"Known compromised package: {name} v{pkg.get('version')}",
                detail=(
                    f"{info['description']}\n"
                    f"  Installed time: {t or 'unknown'} "
                    f"{'(IN breach window!)' if in_window else '(outside breach window — may be clean re-release)'}"
                ),
                ref=info["ref"],
            ))
    return findings


def check_breach_window_timestamps(lock: dict) -> list[Finding]:
    findings = []
    all_pkgs = lock.get("packages", []) + lock.get("packages-dev", [])
    for pkg in all_pkgs:
        t = pkg.get("time", "")[:10]
        if not t:
            continue
        for w_start, w_end, event in BREACH_WINDOWS:
            if w_start <= t <= w_end:
                # Skip known-safe vendors
                name = pkg.get("name", "")
                if any(name.startswith(v) for v in ["symfony/", "laravel/", "illuminate/"]):
                    continue
                findings.append(Finding(
                    severity="MEDIUM",
                    category="breach_window_timestamp",
                    package=name,
                    file="composer.lock",
                    line=None,
                    message=f"Package updated during known breach window: {name} v{pkg.get('version')}",
                    detail=f"Timestamp {t} falls within {event} window ({w_start} – {w_end}). Verify integrity.",
                ))
    return findings


def check_non_zip_dist(lock: dict) -> list[Finding]:
    findings = []
    all_pkgs = lock.get("packages", []) + lock.get("packages-dev", [])
    for pkg in all_pkgs:
        dist = pkg.get("dist", {})
        dist_type = dist.get("type", "")
        if dist_type and dist_type != "zip":
            findings.append(Finding(
                severity="LOW",
                category="non_zip_dist",
                package=pkg.get("name"),
                file="composer.lock",
                line=None,
                message=f"Non-zip dist type '{dist_type}': {pkg.get('name')} v{pkg.get('version')}",
                detail="Packagist normally distributes zips. Path/git dist types may indicate local or tampered packages.",
            ))
    return findings


def check_autoload_files(lock: dict, vendor_path: Path) -> list[Finding]:
    findings = []
    all_pkgs = lock.get("packages", []) + lock.get("packages-dev", [])
    for pkg in all_pkgs:
        name = pkg.get("name", "")
        autoload_files = pkg.get("autoload", {}).get("files", [])
        if not autoload_files:
            continue

        pkg_vendor = vendor_path / name
        for af in autoload_files:
            af_path = pkg_vendor / af
            if not af_path.exists():
                findings.append(Finding(
                    severity="LOW",
                    category="autoload_files",
                    package=name,
                    file=str(af_path),
                    line=None,
                    message=f"autoload.files entry not found on disk: {af}",
                    detail="Could indicate a discrepancy between composer.lock and vendor/.",
                ))
                continue

            # Scan file contents for malicious patterns
            try:
                content = af_path.read_text(errors="replace")
                for pattern, desc in MALICIOUS_PATTERNS:
                    for m in re.finditer(pattern, content, re.IGNORECASE):
                        line_no = content[:m.start()].count("\n") + 1
                        severity = "CRITICAL" if any(k in desc.lower() for k in ["c2", "exfil", "payload", "execution", "flipbox"]) else "HIGH"
                        findings.append(Finding(
                            severity=severity,
                            category="malicious_code",
                            package=name,
                            file=str(af_path),
                            line=line_no,
                            message=f"Suspicious pattern in autoload.files: {desc}",
                            detail=f"Match: {m.group(0)[:120]}",
                        ))
            except Exception as e:
                findings.append(Finding(
                    severity="LOW",
                    category="scan_error",
                    package=name,
                    file=str(af_path),
                    line=None,
                    message=f"Could not scan file: {e}",
                ))
    return findings


def check_vendor_for_c2(vendor_path: Path) -> list[Finding]:
    findings = []
    if not vendor_path.exists():
        return findings

    c2_pattern = "|".join(re.escape(d.replace("[.]", r"\.?")) for d in KNOWN_C2_DOMAINS)
    malware_dir = ".laravel_locale"

    for root, dirs, files in os.walk(vendor_path):
        # Skip test/docs directories
        dirs[:] = [d for d in dirs if d.lower() not in {"test", "tests", "docs", ".git"}]

        for fname in files:
            if not fname.endswith(".php"):
                continue
            fpath = Path(root) / fname
            try:
                content = fpath.read_text(errors="replace")
                if re.search(c2_pattern, content, re.IGNORECASE):
                    line_nos = [i+1 for i,l in enumerate(content.splitlines()) if re.search(c2_pattern, l, re.IGNORECASE)]
                    findings.append(Finding(
                        severity="CRITICAL",
                        category="c2_domain",
                        package=None,
                        file=str(fpath),
                        line=line_nos[0] if line_nos else None,
                        message=f"Known C2 domain found in vendor file",
                        detail=f"Lines: {line_nos[:5]}",
                    ))
                if malware_dir in content:
                    findings.append(Finding(
                        severity="CRITICAL",
                        category="malware_marker",
                        package=None,
                        file=str(fpath),
                        line=None,
                        message=f"Known malware temp-dir marker '.laravel_locale' found",
                    ))
            except Exception:
                pass
    return findings


def run_composer_audit(project_path: Path) -> list[Finding]:
    findings = []
    composer = "composer"

    print(f"\n  {cyan('→')} Running composer audit --no-plugins (safe mode)...")
    try:
        result = subprocess.run(
            [composer, "audit", "--no-plugins", "--format=json"],
            cwd=project_path,
            capture_output=True,
            text=True,
            timeout=60,
        )
        try:
            data = json.loads(result.stdout or "{}")
            advisories = data.get("advisories", {})
            for pkg_name, advs in advisories.items():
                for adv in advs:
                    sev = (adv.get("severity") or "medium").upper()
                    if sev not in ("HIGH", "CRITICAL", "MEDIUM", "LOW"):
                        sev = "MEDIUM"
                    findings.append(Finding(
                        severity=sev,
                        category="cve",
                        package=pkg_name,
                        file="composer.lock",
                        line=None,
                        message=f"CVE: {adv.get('title', 'Unknown')}",
                        detail=(
                            f"CVE: {adv.get('cve', 'N/A')} | "
                            f"Affects: {adv.get('affectedVersions', 'N/A')}"
                        ),
                        ref=adv.get("link", ""),
                    ))
        except json.JSONDecodeError:
            if result.returncode != 0:
                findings.append(Finding(
                    severity="INFO",
                    category="audit",
                    package=None,
                    file=None,
                    line=None,
                    message="composer audit completed (non-JSON output — no vulnerabilities or text output)",
                    detail=result.stdout[:300] if result.stdout else result.stderr[:300],
                ))
    except FileNotFoundError:
        findings.append(Finding(
            severity="INFO",
            category="audit",
            package=None, file=None, line=None,
            message="composer not found in PATH — skipping audit step",
        ))
    except subprocess.TimeoutExpired:
        findings.append(Finding(
            severity="INFO",
            category="audit",
            package=None, file=None, line=None,
            message="composer audit timed out after 60s",
        ))
    return findings


def print_report(findings: list[Finding], project_path: Path):
    print(f"\n{bold('━' * 60)}")
    print(bold(f"  RESULTS for {project_path}"))
    print(bold('━' * 60))

    if not findings:
        print(green("\n  ✓ No issues found. Project appears clean.\n"))
        return

    # Group by severity
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    grouped = {s: [f for f in findings if f.severity == s] for s in order}

    counts = {s: len(grouped[s]) for s in order if grouped[s]}
    summary = "  " + "  ".join(f"{severity_color(s)}: {n}" for s, n in counts.items())
    print(f"\n  Summary: {summary}\n")

    for sev in order:
        for f in grouped[sev]:
            label = severity_color(f"[{f.severity}]")
            cat   = f"({f.category})"
            loc   = ""
            if f.file:
                loc = f.file.replace(str(project_path) + "/", "")
                if f.line:
                    loc += f":{f.line}"
                loc = f"  {cyan(loc)}"

            print(f"  {label} {bold(f.message)}")
            if f.package:
                print(f"  {'':>10} Package : {f.package}")
            if loc:
                print(f"  {'':>10} File    : {loc}")
            if f.detail:
                for line in f.detail.splitlines():
                    print(f"  {'':>10} Detail  : {line}")
            if f.ref:
                print(f"  {'':>10} Ref     : {f.ref}")
            print()

    critical = len(grouped.get("CRITICAL", []))
    high     = len(grouped.get("HIGH", []))
    if critical > 0:
        print(red(bold(f"  ⚠  {critical} CRITICAL finding(s) — treat host as potentially compromised.")))
        print(red("     Rotate all credentials. Rebuild from clean image. Do not run composer commands on this host.\n"))
    elif high > 0:
        print(yellow(f"  ⚠  {high} HIGH finding(s) — review and remediate.\n"))
    else:
        print(green("  ✓  No critical/high issues found.\n"))


def main():
    parser = argparse.ArgumentParser(
        description="Laravel Supply Chain Attack Checker — inspects without executing PHP",
    )
    parser.add_argument(
        "project",
        nargs="?",
        default="/project",
        help="Path to the Laravel project (default: /project)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors (auto-disabled when not a TTY)",
    )
    parser.add_argument(
        "--no-audit",
        action="store_true",
        help="Skip composer audit step",
    )
    parser.add_argument(
        "--no-vendor-scan",
        action="store_true",
        help="Skip deep vendor/ directory scan (faster)",
    )
    args = parser.parse_args()

    if args.no_color:
        global RED, YELLOW, GREEN, CYAN, BOLD, RESET
        RED = YELLOW = GREEN = CYAN = BOLD = RESET = ""

    project_path = Path(args.project).resolve()

    print_banner()
    print(f"\n  {bold('Target:')} {project_path}\n")

    if not project_path.exists():
        print(red(f"  [!] Path does not exist: {project_path}"))
        sys.exit(1)

    lock = load_lock(project_path)
    if lock is None:
        sys.exit(1)

    pkg_count = len(lock.get("packages", [])) + len(lock.get("packages-dev", []))
    print(f"  {green('✓')} Loaded composer.lock — {pkg_count} packages\n")

    findings: list[Finding] = []

    print(f"  {cyan('→')} Checking for known compromised packages...")
    findings += check_known_compromised(lock)

    print(f"  {cyan('→')} Checking for breach-window timestamps...")
    findings += check_breach_window_timestamps(lock)

    print(f"  {cyan('→')} Checking dist types...")
    findings += check_non_zip_dist(lock)

    vendor_path = project_path / "vendor"
    print(f"  {cyan('→')} Scanning autoload.files entries...")
    findings += check_autoload_files(lock, vendor_path)

    if not args.no_vendor_scan:
        print(f"  {cyan('→')} Scanning vendor/ for C2 domains and malware markers...")
        findings += check_vendor_for_c2(vendor_path)

    if not args.no_audit:
        findings += run_composer_audit(project_path)

    print_report(findings, project_path)

    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
    sys.exit(2 if critical_count > 0 else 0)


if __name__ == "__main__":
    main()
