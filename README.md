# winenum

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Language](https://img.shields.io/badge/language-Python%203.8%2B-blue)](https://python.org)
[![Platform](https://img.shields.io/badge/platform-Windows%20Server%202016--2025%20%7C%20Win10%2F11-lightgrey)]()
[![Impacket](https://img.shields.io/badge/powered%20by-Impacket-red)](https://github.com/fortra/impacket)

Remote, read-only Windows posture checks from Kali. No agent, no PowerShell, no process on target. Reads WMI + registry over SMB/MS-RRP and WMI StdRegProv. Reports `UNKNOWN` instead of guessing.

    # klist is enough, no export needed
    kinit administrador@FENIX.LOCAL && klist
    python3 winenum.py FENIX.LOCAL/administrador@dc01.fenix.local -k --dc-ip 192.168.254.174 -v

    # hash or AES key also work
    python3 winenum.py FENIX.LOCAL/administrador@dc01.fenix.local --hashes :NTHASH
    python3 winenum.py FENIX.LOCAL/administrador@dc01.fenix.local --aes-key <hex> --dc-ip 192.168.254.174

    # JSON for automation
    python3 winenum.py FENIX.LOCAL/administrador@dc01.fenix.local -k --dc-ip 192.168.254.174 --json > report.json

## Contents

- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Reference](#quick-reference)
- [Setup Guide](#setup-guide)
- [Walkthrough](#walkthrough)
- [Checks](#checks)
- [Registry Sources](#registry-sources)
- [Transports](#transports)
- [Output](#output)
- [OPSEC](#opsec)
- [Detection](#detection)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Project Layout](#project-layout)
- [License](#license)

## Architecture

```
kali (operator)                         target (Windows)
  |                                         |
  |  TCP 445/135 probe                      |
  |---------------------------------------->|
  |                                         |
  |  SMB auth (NTLM/Kerberos)               |
  |  + MS-RRP \\PIPE\winreg  ──────────────>|  HKLM\SYSTEM, SOFTWARE ...
  |  or                                     |
  |  WMI DCOM ─────────────────────────────>|  root\default:StdRegProv
  |    EnumValues + GetString/DWORD/etc     |  root\Microsoft\Windows\DeviceGuard
  |    Win32_OperatingSystem                |  Win32_ComputerSystem
  |    Win32_DeviceGuard                    |
  |                                         |
  |  <── VALUE / NOT_FOUND / UNAVAILABLE ── |
  |  report: ENABLED / NOT CONFIGURED / UNKNOWN
```

`CompositeTransport` tries MS-RRP first, falls back to StdRegProv only on `UNAVAILABLE` — not on `NOT_FOUND`.

## Installation

```
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt

python3 winenum.py --help          # works even without Impacket installed
python3 -m compileall -q winenum   # syntax check
```

Requires Python 3.8+, Impacket 0.12.0+, network to 445/135. Run from Kali.

## Quick Reference

```
# password (lab)
python3 winenum.py DOMAIN/user:pass@host -v

# pass-the-hash
python3 winenum.py DOMAIN/user@host --hashes LM:NT

# Kerberos ccache (klist is enough, no export)
kinit user@FENIX.LOCAL && klist
python3 winenum.py FENIX.LOCAL/user@dc01.fenix.local -k --dc-ip 192.168.254.174 -v
python3 winenum.py FENIX.LOCAL/user@dc01.fenix.local -k --dc-ip 192.168.254.174 --json > report.json

# AES key
python3 winenum.py FENIX.LOCAL/user@dc01.fenix.local --aes-key <hex> --dc-ip 192.168.254.174 -v

# verbose + json
python3 winenum.py DOMAIN/user@host -k --dc-ip 192.168.254.174 -v --json | jq .
```

## Setup Guide

### 1. Lab network

Target: Windows Server 2016/2019/2022/2025 or Win10/11. Account needs remote registry / DCOM rights. No agent install.

### 2. Kerberos (optional, for `-k`)

```
# /etc/krb5.conf
[libdefaults]
  default_realm = FENIX.LOCAL
[realms]
  FENIX.LOCAL = { kdc = dc01.fenix.local }
[domain_realm]
  .fenix.local = FENIX.LOCAL

# /etc/hosts
192.168.254.174 dc01.fenix.local
```

```
kinit administrador@FENIX.LOCAL
klist
# Ticket cache: FILE:/tmp/krb5cc_1000  <- winenum auto-finds this, no export needed
# KRB5CCNAME export still works and wins if set (including DIR::)
```

Always use FQDN with `-k`. IP gives `KDC_ERR_S_PRINCIPAL_UNKNOWN` (`host/192.168.x.x` has no SPN).

### 3. Test

```
python3 winenum.py FENIX.LOCAL/administrador@dc01.fenix.local -k --dc-ip 192.168.254.174 -v
python3 winenum.py FENIX.LOCAL/administrador@dc01.fenix.local -k --dc-ip 192.168.254.174 --json > report.json && jq . report.json
```

## Walkthrough

```
$ python3 winenum.py FENIX.LOCAL/administrador@dc01.fenix.local -k --dc-ip 192.168.254.174 -v

  winenum v0.2.0
  Windows security configuration enumeration

[*] Target: dc01.fenix.local
[*] User: FENIX.LOCAL\administrador
[*] Kerberos: enabled (ccache: /tmp/krb5cc_1000) KDC: 192.168.254.174
[DEBUG] Using KRB5CCNAME autodetected: /tmp/krb5cc_1000
[*] Checking ports on dc01.fenix.local...
[DEBUG] Stage 1: SMB/MS-RRP registry transport...
[DEBUG] RemoteRegistry unavailable: STATUS_PIPE_NOT_AVAILABLE
[DEBUG] Stage 2: WMI/DCOM transport...
[+] Connected via WMI/DCOM
[*] Connected via CompositeTransport (transport: composite)

============================================================
  SYSTEM INFORMATION
============================================================
      Computer Name       : DC01
      Domain              : fenix.local
      OS Version          : Microsoft Windows Server 2025 Standard Evaluation (Build 26100)
      Product Type        : 2
      Domain Role         : 5
Detected: Windows Server 2025 (Build 26100; domain controller)

============================================================
  LSA PROTECTIONS
============================================================
  [+] PPL (RunAsPPL)      : ENABLED
      PPL Boot Lock       : NOT CONFIGURED
  [!] Credential Guard    : DISABLED
      VBS Status          : NOT CONFIGURED

============================================================
  ASSESSMENT
============================================================
  [!] 0 critical, 13 warnings, 5 protections confirmed, 3 unknown
[*] Enumeration complete.
```

Without `-v`: no `[DEBUG]`, no `Stage` lines, no blank `[*]`. With `--json`: only JSON on stdout.

## Checks

| group | what it reads | key detail |
|-------|---------------|------------|
| System | WMI `Win32_OperatingSystem`, `Win32_ComputerSystem` + registry fallback `Windows NT\CurrentVersion`, `ProductOptions` | Build/edition/role for gating |
| LSA | `RunAsPPL`, `RunAsPPLBoot`, `RunAsPPLMode`, `LsaCfgFlags`, `DeviceGuard\Scenarios` | WMI `SecurityServicesRunning` preferred, registry `Enabled=1` = `CONFIGURED` |
| Kernel | `SecureBoot\State`, `Memory Management\DisableNx`, `kernel\DisableExceptionChainValidation`, `CETEnabled`, `SystemStartOptions` | HVCI via WMI ID 2 |
| Defender | `Windows Defender\Real-Time Protection`, `Spynet`, `ASR Rules` | Ids/Actions pair |
| Drivers | `CI\Config\VulnerableDriverBlocklistEnable`, `VerifiedAndReputablePolicyState` | WDAC state |
| LSA Packages | `Lsa\Authentication Packages`, `Security Packages` | REG_MULTI_SZ, empty strings filtered |
| Network | `LanmanServer\Parameters`, `NTDS`, `Netlogon\Parameters`, `RDP-Tcp`, `Lsa\LmCompatibilityLevel` | LDAP/Kerberos DC-only |
| Kerberos | `Lsa\Kerberos\Parameters`, `Services\Kdc` | `SupportedEncryptionTypes` bitmask |
| LAPS | `Policies\Microsoft\Psd\Laps` | Requires build check `(build or 0)` |
| SmartScreen | `Policies\Windows\System\EnableSmartScreen` | Explorer fallback |

Build-gated: `NOT SUPPORTED` if OS can't have it. Role-gated: `NOT APPLICABLE` on member/client for DC keys.

## Registry Sources

Every read returns one state — no guessing:

| state | meaning | reported as |
|-------|---------|-------------|
| `VALUE` | backend OK, value present | `ENABLED` / `DISABLED` / `CONFIGURED` |
| `NOT_FOUND` | backend OK, value absent | `NOT CONFIGURED` / `DISABLED (not installed)` |
| `ACCESS_DENIED` | permission denied | `UNKNOWN` |
| `UNAVAILABLE` | transport/backend down | `UNKNOWN` |

MS-RRP path: `\\PIPE\winreg` via `hOpenLocalMachine` + `hBaseRegOpenKey` + `hBaseRegQueryValue`. StdRegProv path: `EnumValues` to get `Types[]` then `GetStringValue` / `GetDWORDValue` / `GetMultiStringValue` etc. in `root\default` (fallback `root\cimv2`). Results cached per `(key, value)`.

Concrete keys: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` (ProductName, EditionID, CurrentBuildNumber), `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`, `... \DeviceGuard`, `... \SecureBoot\State`, `... \Services\LanmanServer\Parameters`, `... \Services\NTDS`, `... \Services\Kdc`, `HKLM\SOFTWARE\Policies\Microsoft\Psd\Laps`, etc.

## Transports

```
445 + \\PIPE\winreg  -> SMB/MS-RRP      (fastest, registry only)
else 135            -> WMI/DCOM        (StdRegProv + WMI)
else both           -> Composite       (WMI + SMB registry)
else 445            -> MS-RPC LSA      (last resort)
```

Port probe is TCP connect to 88/135/389/445/636/3389/5985. SMB dialect/signing from real SMB negotiation, not just port.

## Output

Values: `ENABLED` / `DISABLED` / `CONFIGURED` / `NOT CONFIGURED` / `UNKNOWN` / `NOT SUPPORTED` / `NOT APPLICABLE`. `UNKNOWN` is missing evidence, not a finding.

```
usage: winenum.py [-h] [--timeout TIMEOUT] [--verbose] [--json]
                  [--hashes LMHASH:NTHASH] [--no-pass] [--aes-key HEX]
                  [-k] [--dc-ip IP] target
  target  [domain/]user[:pass]@host   (FQDN with -k)
  -v      verbose, shows [DEBUG] Stage lines
  --json  only JSON to stdout
```

JSON top-level: `tool`, `target`, `transport`, `assessment: {level, message}`, `results: {SystemCheck: {...}, ...}`. `UNKNOWN` stays `UNKNOWN`.

## OPSEC

| surface | mitigation |
|---------|------------|
| PowerShell logging (4104, AMSI) | none — no PowerShell, no remote process |
| Process creation | none — no WinRM, no scheduled task, no file write |
| Registry access | MS-RRP `\\PIPE\winreg` or WMI `StdRegProv` — normal admin channels |
| Network | 1-2 sessions, tiered transport, no `IPC$` wildcard |
| Creds | no password in PowerShell CLI, no material on disk; Kerberos via ccache/KRB5CCNAME |

Still logged as normal admin: Kerberos TGS 4769 / NTLM 4624, DCOM/WMI logon, SMB session, `winreg` object access if audited.

## Detection

For defenders — what to look for:

1. Single SMB + WMI/DCOM logon from Kali host at polling time, no PowerShell child processes.
2. `\\PIPE\winreg` access or WMI `StdRegProv` (`root\default`) queries from same source.
3. Kerberos TGS for `host/dc01.fenix.local` or `cifs/dc01.fenix.local` from operator principal.
4. No `powershell.exe` / `pwsh` with ScriptBlock 4104 for these checks.

## Limitations

- No LDAP/SPN graph, no AD CS, no share/group enumeration.
- No `--checks` selector — full suite each run.
- Port scan is TCP reachability; service certainty from handshake.
- SMB signing fallback to live negotiation if registry unreadable; FASP/PAK `UNKNOWN` if DC GPO doesn't expose keys.
- LAPS cloud-only may not appear in local policy keys.
- No large integration suite — validate against disposable lab vs `gpresult`.

## Troubleshooting

**`KDC_ERR_S_PRINCIPAL_UNKNOWN`** — use FQDN, not IP. `host/192.168.x.x` has no SPN.

**`KDC_ERR_PREAUTH_FAILED`** — ccache principal mismatch or wrong AES/hash. Check `klist`, `KRB5CCNAME` not mixing `FENIX` vs `FENIX.LOCAL`.

**`Failed to connect`** — 445/135 not reachable or creds lack DCOM/registry rights. Check `KRB5CCNAME` auto-detect with `-v`: `Using KRB5CCNAME autodetected: ...`.

**All `UNKNOWN` / `System: UNKNOWN`** — SMB auth OK but `winreg` + `StdRegProv` unreadable. Check Remote Registry / WMI permissions, firewall, GPO blocking `root\default`.

**`CONFIGURED (0)` or `"" : Loaded`** — fixed: `0` now `NOT CONFIGURED`, empty LSA package strings filtered.

**`Check failed: '>=' not supported ... NoneType and int`** — fixed: `build` now `(build or 0)` checked.

## Project Layout

```
winenum.py
requirements.txt
README.md
winenum/
  cli.py
  enum.py
  connection/auto.py, composite.py, smb.py, wmi.py, rpc.py, registry.py
  checks/system.py, lsa.py, kernel.py, defender.py, drivers.py, lsa_packages.py, ports.py, network.py, kerberos.py, laps.py, smartscreen.py
  output/console.py
  utils/__init__.py, os_target.py, krb5.py
```

## License

MIT. Use only on systems you own or are authorized to assess.

---
