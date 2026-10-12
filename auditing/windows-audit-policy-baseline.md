# Windows Audit Policy Baseline

> Which Windows advanced audit policy subcategories to enable, why, and how an auditor verifies them. Companion to the [Windows auditing mind maps](Windows-auditing-mindmap-main/README.md) and the [technical control audit tests](technical-control-tests/README.md).

Default Windows auditing records very little. Most organisations only find this out during an incident, when the 4688 process events or 4769 Kerberos events they need were never recorded. This baseline closes that gap.

**Sources:** values below follow the CIS Microsoft Windows Server 2022 Benchmark (Level 1) and the Microsoft Security Baselines, with notes from detection engineering practice. Always compare with the current version of the benchmark you are assessed against. Values marked **DC** apply to domain controllers only.

---

## 1. Prerequisite settings

These must be in place, or the subcategory settings below are ignored or incomplete.

| Setting | Required value | Verify |
|---------|----------------|--------|
| Audit: Force audit policy subcategory settings to override audit policy category settings | Enabled | `reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v SCENoApplyLegacyAuditPolicy` → `0x1` |
| Include command line in process creation events | Enabled | `reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled` → `0x1` |
| PowerShell Script Block Logging | Enabled | `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging` → `0x1` |
| PowerShell Module Logging (recommended) | Enabled, modules `*` | `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging /v EnableModuleLogging` |
| Security event log maximum size | ≥ 196,608 KB (CIS); larger on DCs | `wevtutil gl Security` → `maxSize` |
| Security log retention behaviour | Overwrite as needed **and** forwarded to the SIEM | `wevtutil gl Security` → `retention: false` |

> Command-line logging and script-block logging can capture secrets that are passed on the command line. Restrict who can read these logs in the SIEM.

---

## 2. Advanced audit policy subcategories

S = Success, F = Failure.

### Account Logon
| Subcategory | Setting | Key events | Why it matters |
|-------------|---------|-----------|----------------|
| Credential Validation | S + F | 4776 | NTLM authentication, password spraying |
| Kerberos Authentication Service | S + F (**DC**) | 4768, 4771 | TGT requests, AS-REP roasting, brute force |
| Kerberos Service Ticket Operations | S + F (**DC**) | 4769 | Kerberoasting (RC4 ticket requests) |

### Account Management
| Subcategory | Setting | Key events | Why it matters |
|-------------|---------|-----------|----------------|
| Application Group Management | S + F | 4783–4792 | Changes to application groups |
| Computer Account Management | S (**DC**) | 4741, 4742, 4743 | Rogue computer accounts (RBCD attacks) |
| Distribution Group Management | S (**DC**) | 4749–4753 | Changes to distribution groups |
| Other Account Management Events | S | 4782, 4793 | Password hash accessed, password policy API checks |
| Security Group Management | S | 4728, 4732, 4756 | **Privileged group changes** |
| User Account Management | S + F | 4720, 4722, 4724, 4738, 4740 | Account creation, password resets, lockouts |

### Detailed Tracking
| Subcategory | Setting | Key events | Why it matters |
|-------------|---------|-----------|----------------|
| Plug and Play Events | S | 6416 | USB / external device connected |
| Process Creation | S | 4688 | **Every process started, with its command line.** The most valuable event for detection |
| Process Termination | No auditing (optional S) | 4689 | High volume; enable only if the SIEM can absorb it |
| DPAPI Activity | No auditing (optional S + F) | 4692–4695 | Credential theft research |

### DS Access (domain controllers)
| Subcategory | Setting | Key events | Why it matters |
|-------------|---------|-----------|----------------|
| Directory Service Access | F (CIS), S + F if SACLs are tuned | 4662 | DCSync detection (needs SACL on the domain root) |
| Directory Service Changes | S | 5136, 5137, 5141 | GPO and AD object modifications |

### Logon/Logoff
| Subcategory | Setting | Key events | Why it matters |
|-------------|---------|-----------|----------------|
| Account Lockout | F | 4625 (lockout status) | Brute force |
| Group Membership | S | 4627 | Groups in each logon token |
| Logoff | S | 4634, 4647 | Session duration |
| Logon | S + F | 4624, 4625, 4648 | **Who logged on, from where, and how** (logon type) |
| Other Logon/Logoff Events | S + F | 4778, 4779, 4800, 4801 | RDP reconnects, workstation lock and unlock |
| Special Logon | S | 4672, 4964 | **Admin logons** |

### Object Access
| Subcategory | Setting | Key events | Why it matters |
|-------------|---------|-----------|----------------|
| Detailed File Share | F | 5145 | Failed share access (S is very noisy) |
| File Share | S + F | 5140 | Share access, lateral movement |
| File System | Per SACL (sensitive folders only) | 4663 | Access to sensitive data |
| Other Object Access Events | S + F | 4698–4702 | **Scheduled task created or modified** |
| Removable Storage | S + F | 4663 | Data copied to USB |
| SAM | Optional | 4661 | SAM handle requests |

### Policy Change
| Subcategory | Setting | Key events | Why it matters |
|-------------|---------|-----------|----------------|
| Audit Policy Change | S | **4719**, 4907 | Attacker disabling auditing |
| Authentication Policy Change | S | 4706, 4713, 4716 | Trust and Kerberos policy changes |
| Authorization Policy Change | S | 4703, 4704 | User rights assigned |
| MPSSVC Rule-Level Policy Change | S + F | 4946–4950 | Windows Firewall rules changed |
| Other Policy Change Events | F | 6144, 6145 | GPO processing errors |

### Privilege Use
| Subcategory | Setting | Key events | Why it matters |
|-------------|---------|-----------|----------------|
| Sensitive Privilege Use | S + F | 4673, 4674 | Use of SeDebugPrivilege and similar |

### System
| Subcategory | Setting | Key events | Why it matters |
|-------------|---------|-----------|----------------|
| IPsec Driver | S + F | 4960–4963 | Integrity failures |
| Other System Events | S + F | 5024, 5025 | Firewall service start/stop |
| Security State Change | S | 4608, 4616 | Startup, **system time changed** |
| Security System Extension | S | **4697** | **Service installed** (persistence, PsExec) |
| System Integrity | S + F | 4612, 5038 | Dropped audit events, code integrity |

### Outside the Security log, but equally important

| Log | Event | Why |
|-----|-------|-----|
| System | 7045 | New service installed |
| System | 104 | Event log cleared |
| Security | **1102** | Security log cleared |
| Microsoft-Windows-PowerShell/Operational | 4103, **4104** | Module and script block logging |
| Microsoft-Windows-TaskScheduler/Operational | 106, 140, 141 | Task registered, updated, deleted |
| Microsoft-Windows-Windows Defender/Operational | 1116, 1117, 5001 | Malware detected and acted on; real-time protection **disabled** |
| Microsoft-Windows-Sysmon/Operational | 1, 3, 11, 13... | If Sysmon is deployed: richer process, network, file and registry telemetry |

---

## 3. Audit procedure

### WIN-AUD-01 · Baseline is defined and deployed centrally
**Procedure:** Get the GPO (or Intune profile) that sets advanced audit policy and the OUs it is linked to. Confirm every in-scope OU is covered and that no other GPO conflicts with it.
```powershell
Get-GPOReport -All -ReportType Html -Path .\all_gpos.html   # requires GroupPolicy module
gpresult /h .\gpresult_%COMPUTERNAME%.html                  # on a sampled host
```
| Pass | Fail |
|------|------|
| One authoritative GPO or profile, linked to all in-scope OUs | No central policy, or conflicting GPOs |

### WIN-AUD-02 · Effective policy on sampled hosts matches the baseline
**Procedure:** Sample hosts from each role (DC, member server, workstation, critical app server). Run the following on each and compare with the tables above.
```powershell
# Effective advanced audit policy, as CSV
auditpol /get /category:* /r > "$env:COMPUTERNAME-auditpol.csv"

# Prerequisites
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v SCENoApplyLegacyAuditPolicy
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit /v ProcessCreationIncludeCmdLine_Enabled
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging /v EnableScriptBlockLogging
wevtutil gl Security
```

**Compare automatically** against a baseline CSV (`Subcategory,Expected`, where Expected is one of `Success`, `Failure`, `Success and Failure` or `No Auditing`):
```powershell
$baseline = Import-Csv .\baseline.csv
$actual   = auditpol /get /category:* /r | ConvertFrom-Csv
foreach ($b in $baseline) {
  $a = $actual | Where-Object { $_.Subcategory -eq $b.Subcategory }
  if ($a.'Inclusion Setting' -ne $b.Expected) {
    [pscustomobject]@{ Subcategory = $b.Subcategory; Expected = $b.Expected; Actual = $a.'Inclusion Setting' }
  }
}
```
> `auditpol` output is localised. Run it on English-language systems, or map the subcategory names. Treat "Success and Failure" as meeting an "S" requirement only if your firm accepts it; it usually does, at the cost of extra volume.

| Pass | Fail |
|------|------|
| All sampled hosts meet or exceed the baseline | Subcategories missing (commonly 4688 command line, 4769 on DCs, 4698) |

### WIN-AUD-03 · Events are actually generated and collected
**Procedure:** For each key event (4624, 4625, 4688, 4720, 4728, 4698, 4719, 1102, 4104), prove that it exists **in the SIEM** for sampled hosts over the last 7 days. A policy being set does not prove that events are flowing.
```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4624, 4625, 4672, 4688, 4697, 4698, 4719, 4720, 4728, 4732, 4756, 4768, 4769, 1102)
| summarize Count = count() by EventID, Computer
| order by Computer, EventID
```
```spl
index=wineventlog EventCode IN (4624,4625,4672,4688,4697,4698,4719,4720,4728,4732,4756,4768,4769,1102) earliest=-7d
| stats count by host EventCode
```
| Pass | Fail |
|------|------|
| Expected events are present from all sampled hosts (4768/4769 from DCs) | Policy set but events missing, often because the forwarder filters them out |

### WIN-AUD-04 · Audit policy changes are detected
**Procedure:** Confirm there is a SIEM alert on **4719** (audit policy changed) and **1102** (log cleared). Review all occurrences in the period, and match each one to a change ticket.

| Pass | Fail |
|------|------|
| An alert exists; every occurrence is explained | No alerting, or unexplained changes |

---

## 4. Common findings

| Finding | Risk |
|---------|------|
| Process Creation (4688) not enabled, or command line not captured | Cannot see what attackers executed; most detections and investigations are blind |
| Kerberos Service Ticket Operations not enabled on DCs | Kerberoasting goes undetected |
| Security log at the default size, and not forwarded | Evidence overwritten within hours on busy servers |
| Legacy category policy applied without the override setting | Subcategory settings silently ignored |
| Workstations excluded from the baseline ("servers only") | Initial access usually happens on endpoints |
| Forwarder filters out events the baseline enables | Logged locally but never reaches detection |

---

**Mapping:** ISO 27001:2022 A.8.15 · NIST CSF 2.0 PR.PS-04 · CIS v8 Safeguards 8.2, 8.5, 8.8 · PCI DSS v4.0 Req. 10.2
