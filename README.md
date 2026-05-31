# Laravel Supply Chain Attack Checker

A zero-execution security scanner for Laravel projects that detects supply chain compromises, known malicious packages, and CVEs — **without booting PHP or running any project code**.

> Inspired by the May 2026 `laravel-lang` tag-rewrite attack that injected a credential stealer into ~700 package versions via a leaked GitHub PAT.  
> [Read the advisory →](https://snyk.io/blog/laravel-lang-supply-chain-advisory/)

---

## Why "zero-execution"?

The `laravel-lang` attack injected malware into `autoload.files` — a Composer mechanism that runs PHP files **automatically on every request**. This means:

- Running `php artisan`, `composer install`, or even `composer audit` on an infected host **triggers the malware**
- The malware exfiltrates AWS/GCP/Azure keys, SSH keys, `.env` files, browser passwords, and CI/CD tokens to a remote C2 server

This tool inspects `composer.lock` and `vendor/` as **static files only** — no PHP process is ever started.

---

## What it checks

| Check | Description |
|---|---|
| **Known compromised packages** | Matches against a database of packages with confirmed supply chain incidents |
| **Breach-window timestamps** | Flags packages updated during known attack windows in `composer.lock` |
| **Non-zip dist types** | Detects path/git dist entries that bypass Packagist integrity |
| **`autoload.files` scan** | Scans every file registered in `autoload.files` for malicious patterns (remote fetch, exec, eval, C2 domains) |
| **Vendor C2 scan** | Searches all `.php` files in `vendor/` for known C2 domains and malware markers |
| **`composer audit --no-plugins`** | Runs the official CVE check in safe mode (plugins disabled) |

### Malicious patterns detected

- `eval(base64_decode(...))` — obfuscated payload execution
- `file_get_contents('https://...')` — remote payload fetch
- `curl_exec`, `fsockopen` — data exfiltration
- `shell_exec`, `system`, `passthru`, `proc_open` — OS command execution
- Known C2 domains (e.g. `flipboxstudio.info`)
- Known malware temp-dir markers (`.laravel_locale`)

---

## Requirements

- [Docker](https://docs.docker.com/get-docker/) — the only requirement on the host

---

## Installation

```bash
git clone https://github.com/your-username/laravel-sca-checker.git
cd laravel-sca-checker

# Build the Docker image (one-time)
docker build -t laravel-sca-checker .
```

---

## Usage

### Linux / macOS / WSL2 / Git Bash

```bash
chmod +x check.sh
./check.sh /path/to/your/laravel-project
```

### Windows PowerShell

```powershell
.\check.ps1 C:\path\to\your\laravel-project
```

### Windows CMD

```bat
check.bat C:\path\to\your\laravel-project
```

### Docker directly

```bash
docker run --rm \
  -v /path/to/laravel-project:/project:ro \
  laravel-sca-checker /project
```

### Docker Compose

```bash
PROJECT_PATH=/path/to/laravel-project docker compose run --rm checker
```

---

## Options

| Flag | Description |
|---|---|
| `--no-audit` | Skip `composer audit` (pure static analysis, safest on a suspected host) |
| `--no-vendor-scan` | Skip deep `vendor/` scan (faster, still checks `autoload.files`) |
| `--no-color` | Disable ANSI colors (auto-disabled when output is not a TTY) |

```bash
# Fastest — static only, no network, no composer
./check.sh /path/to/project --no-audit --no-vendor-scan

# Safest on a potentially infected host — no PHP, no plugins
./check.sh /path/to/project --no-audit
```

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Clean — no critical or high findings |
| `1` | Error (missing `composer.lock`, invalid path) |
| `2` | **CRITICAL finding** — treat host as potentially compromised |

Useful for CI pipelines:

```yaml
# GitHub Actions example
- name: Laravel supply chain check
  run: |
    docker build -t laravel-sca-checker .
    docker run --rm -v ${{ github.workspace }}:/project:ro laravel-sca-checker /project --no-color
```

---

## Example output

```
╔══════════════════════════════════════════════════════╗
║      Laravel Supply Chain Attack Checker             ║
║      Inspects without executing any PHP code         ║
╚══════════════════════════════════════════════════════╝

  Target: /project

  ✓ Loaded composer.lock — 140 packages

  → Checking for known compromised packages...
  → Checking for breach-window timestamps...
  → Checking dist types...
  → Scanning autoload.files entries...
  → Scanning vendor/ for C2 domains and malware markers...
  → Running composer audit --no-plugins (safe mode)...

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  RESULTS for /project
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Summary:   CRITICAL: 1

  [CRITICAL] Known compromised package: laravel-lang/lang v6.1.0
             Package : laravel-lang/lang
             File    : composer.lock
             Detail  : Credential stealer via autoload.files (tag rewrite attack)
                       Installed time: 2026-05-22 (IN breach window!)
             Ref     : https://snyk.io/blog/laravel-lang-supply-chain-advisory/

  ⚠  1 CRITICAL finding(s) — treat host as potentially compromised.
     Rotate all credentials. Rebuild from clean image. Do not run composer commands on this host.
```

---

## If CRITICAL is found — immediate steps

1. **Do not run any more commands on this host** — every PHP execution re-triggers the malware
2. **Rotate all credentials immediately**: AWS/GCP/Azure keys, `.env` secrets, SSH keys, database passwords, API tokens
3. **Rebuild from a clean image** — do not attempt to clean the infected vendor directory in place
4. **Pull `composer.lock` to a clean machine** and run the checker there with `--no-vendor-scan`
5. **Audit your SCM and CI/CD** — the malware also targets GitHub tokens and CI secrets
6. **Block the C2 domain** at the network/firewall level: `flipboxstudio.info`

---

## Adding new attack signatures

Edit the relevant section in `checker.py`:

```python
# Known compromised packages
KNOWN_COMPROMISED: dict[str, dict] = {
    "vendor/package": {
        "window": ("YYYY-MM-DD", "YYYY-MM-DD"),
        "description": "Brief description of the attack",
        "ref": "https://link-to-advisory",
    },
}

# Known C2 / exfiltration domains
KNOWN_C2_DOMAINS = [
    "malicious-domain.com",
]

# Malicious code patterns (regex, description)
MALICIOUS_PATTERNS = [
    (r"your_pattern_here", "Description of what this detects"),
]
```

Pull requests with new signatures are welcome.

---

## Compatibility

| Platform | Wrapper | Status |
|---|---|---|
| Linux | `./check.sh` | ✅ |
| macOS | `./check.sh` | ✅ (no `realpath` dependency) |
| WSL2 | `./check.sh` | ✅ |
| Git Bash (Windows) | `./check.sh` | ✅ |
| PowerShell (Windows) | `.\check.ps1` | ✅ |
| CMD (Windows) | `check.bat` | ✅ |

---

## References

- [Snyk Advisory — laravel-lang supply chain attack](https://snyk.io/blog/laravel-lang-supply-chain-advisory/)
- [StepSecurity — Attack analysis](https://www.stepsecurity.io/blog/laravel-lang-supply-chain-attack)
- [Aikido Security — Technical breakdown](https://www.aikido.dev/blog/supply-chain-attack-targets-laravel-lang-packages-with-credential-stealer)
- [Packagist — Composer security update](https://blog.packagist.com/an-update-on-composer-packagist-supply-chain-security/)

---

## License

MIT
