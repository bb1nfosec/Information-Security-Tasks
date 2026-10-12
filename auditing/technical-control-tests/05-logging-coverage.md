# Audit Tests — Logging Coverage, Configuration & Retention

> The SIEM can only detect what systems actually log. This program tests the **source side**: is each system configured to generate the right events, forward them, timestamp them correctly, and keep them?

**Control objective:** All in-scope systems generate security-relevant audit logs per the logging standard, forward them to central storage, use synchronised time, and retain logs for the required period with integrity protection.

**Evidence to request up front**
- Logging standard: which events, from which system types, with what retention
- Asset inventory by platform (Windows, Linux, network, database, cloud, SaaS, applications)
- Log forwarding architecture (agents, syslog relays, cloud connectors)
- NTP architecture

---

## LOG-01 · Logging standard defines required events per platform

**Objective (test of design):** The standard states *what* must be logged. "Enable logging" is not enough.

Minimum event categories the standard should require:

| Category | Examples |
|----------|----------|
| Authentication | Success and failure logons, MFA events, lockouts |
| Account & privilege management | User or group create, delete and modify; privilege grants |
| Privileged activity | Admin commands, `sudo`, PowerShell, database DBA actions |
| Security configuration changes | Audit policy change, firewall rule change, security tool disabled |
| Data access | Access to sensitive data (files, DB tables, SaaS) |
| System events | Start/stop, service install, log cleared, time change |
| Network | Firewall allow/deny, VPN, proxy, DNS |
| Application | Business-critical transactions, app admin changes |

Each event record must capture **who, what, when (synchronised time), where (source and destination), and outcome**.

| Pass | Fail |
|------|------|
| Platform-specific event requirements defined | A generic one-liner with no event-level detail |

---

## LOG-02 · Windows audit configuration

**Objective:** Windows servers and workstations have the baseline advanced audit policy applied, and it is not overridden.

Full baseline and commands: **[Windows Audit Policy Baseline](../windows-audit-policy-baseline.md)**

**Quick evidence (run on sampled hosts)**
```powershell
auditpol /get /category:* /r | ConvertFrom-Csv | Select-Object "Subcategory","Inclusion Setting" |
  Export-Csv "$env:COMPUTERNAME-auditpol.csv" -NoTypeInformation
Get-WinEvent -ListLog Security | Select-Object LogName, MaximumSizeInBytes, LogMode
```

| Pass | Fail |
|------|------|
| Sampled hosts match the baseline, applied centrally through GPO or Intune | Default "Success only" policy, or settings applied host by host and drifting |

---

## LOG-03 · Linux / Unix audit configuration

**Objective:** Linux hosts run auditd with rules that cover the standard, and forward their logs.

**Evidence**
```bash
systemctl is-active auditd rsyslog 2>/dev/null
auditctl -s                       # "enabled 1" (or 2 = locked, rules immutable until reboot)
auditctl -l                       # loaded rules: look for identity, sudoers, exec, time-change and module rules
grep -E "^\s*(max_log_file|num_logs|max_log_file_action|space_left_action)" /etc/audit/auditd.conf

# Forwarding (rsyslog): @ = UDP, @@ = TCP
grep -rhE "^\s*[^#].*@{1,2}[A-Za-z0-9.-]+" /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null
```

**Rules you would expect to see** (from the CIS Benchmarks for Linux):
```bash
-w /etc/passwd -p wa -k identity
-w /etc/group  -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /var/log/sudo.log -p wa -k actions
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
-a always,exit -F arch=b64 -S execve -F euid=0 -F auid>=1000 -F auid!=unset -k root_cmds
```

| Pass | Fail |
|------|------|
| auditd active with rules covering the standard; logs forwarded over TCP/TLS | auditd off or with no rules; local logs only |

---

## LOG-04 · Cloud & SaaS audit logs

**Objective:** Control-plane and identity logs are enabled for every cloud account, subscription and SaaS tenant, and are collected centrally.

**AWS — CloudTrail**
```bash
aws cloudtrail describe-trails \
  --query "trailList[].{Name:Name,MultiRegion:IsMultiRegionTrail,OrgTrail:IsOrganizationTrail,Validation:LogFileValidationEnabled,KMS:KmsKeyId,Bucket:S3BucketName}" \
  --output table
aws cloudtrail get-trail-status --name <trail> --query "{IsLogging:IsLogging,LatestDelivery:LatestDeliveryTime}"
```
Expected: an organisation-wide, multi-region trail, with log file validation on, KMS encryption, and delivery to a locked-down bucket in a separate log-archive account.

**Azure — Activity log & Entra ID**
```bash
# Subscription activity log exported to Log Analytics / storage
az monitor diagnostic-settings subscription list -o table
```
Entra ID → Monitoring → Diagnostic settings: `SignInLogs`, `AuditLogs`, `NonInteractiveUserSignInLogs`, `ServicePrincipalSignInLogs` and `RiskyUsers` should be sent to the SIEM workspace.

**Microsoft 365 — Unified Audit Log**
```powershell
Connect-ExchangeOnline
Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled
# Mailbox auditing on by default?
Get-OrganizationConfig | Format-List AuditDisabled
```
Expected: `UnifiedAuditLogIngestionEnabled : True` and `AuditDisabled : False`.

**GCP**
```bash
gcloud logging sinks list
gcloud projects get-iam-policy <project> --format=json | jq '.auditConfigs'   # Data Access logs enabled?
```

| Pass | Fail |
|------|------|
| Every account and tenant is logged and centralised, with integrity validation on | Regions, accounts or subscriptions not covered; UAL disabled |

---

## LOG-05 · End-to-end forwarding test

**Objective:** An event generated on a sampled system actually arrives in the SIEM, complete and on time.

**Procedure:** On each sampled host (one per platform type), generate a harmless, uniquely tagged event, then search for it in the SIEM and record the latency.

```powershell
# Windows: writes event ID 999 to the Application log
eventcreate /T INFORMATION /ID 999 /L APPLICATION /SO AuditTest /D "AUDIT-TEST-<ticket-no> $(Get-Date -Format o)"
```
```bash
# Linux
logger -p auth.notice "AUDIT-TEST-<ticket-no> $(date -Is)"
```
```spl
index=* "AUDIT-TEST-<ticket-no>" | table _time _indextime host source
```
```kql
search "AUDIT-TEST-<ticket-no>" | project TimeGenerated, $table, Computer
```

| Pass | Fail |
|------|------|
| The event arrives within minutes, with the correct host and time | Event never arrives, arrives hours later, or with the wrong host or timestamp |

---

## LOG-06 · Time synchronisation

**Objective:** All systems synchronise to an authoritative time source, so logs correlate. In India, CERT-In requires synchronisation to NIC or NPL NTP servers, or to servers traceable to them.

**Evidence**
```powershell
w32tm /query /status          # Source, Stratum, Last Successful Sync Time
w32tm /query /configuration   # NtpServer, Type (NT5DS = domain hierarchy)
```
```bash
timedatectl status            # "System clock synchronized: yes"
chronyc tracking              # Reference ID, System time offset
chronyc sources -v
```
**Procedure:** Trace the hierarchy: workstations → DCs → PDC emulator → external source. Confirm the top-level source is authoritative (e.g. `time.nplindia.org`, or NIC servers) and that network devices and cloud VMs use the same hierarchy or a provider time service.

| Pass | Fail |
|------|------|
| All sampled systems synchronised, offset under 1 s, top source authoritative | Unsynchronised hosts, the PDC on its local CMOS clock, or mixed sources |

---

## LOG-07 · Log retention & storage location

**Objective:** Logs are retained for the required period, and stored where the law requires.

**Procedure**
1. Central retention: see [SIEM-02](01-siem.md#siem-02--log-retention).
2. Local buffers: is the local log size big enough to survive a forwarding outage of, say, 7 days? Check the Windows Security log size and auditd `max_log_file × num_logs`.
3. Data location: confirm that the SIEM workspace, storage region and archive meet the 180-day CERT-In retention **within Indian jurisdiction**. Check cloud region settings, and also the contracts for MSSPs or SaaS SIEMs.

```bash
az monitor log-analytics workspace show -g <rg> -n <workspace> --query "{region:location, retentionDays:retentionInDays}"
```

| Pass | Fail |
|------|------|
| Retention ≥ requirement for every source; storage location compliant | Retention gaps, or logs held only outside the required jurisdiction |

---

## LOG-08 · Log integrity & protection

**Objective:** Logs cannot be altered or deleted by the people whose actions they record.

| Check | Evidence |
|-------|----------|
| Admins of monitored systems cannot delete logs in the SIEM or archive | SIEM role review ([SIEM-07](01-siem.md#siem-07--siem-access--tamper-protection)) |
| Log clearing raises an alert | Rule for Windows **1102** (Security log cleared) and **104** (System log cleared); Linux auditd watch on `/var/log/audit/` |
| Audit policy changes raise an alert | Windows **4719** (system audit policy changed) |
| Cloud trail tampering raises an alert | CloudTrail `StopLogging`, `DeleteTrail`, `UpdateTrail`; Azure diagnostic setting deletion |
| Archive storage is write-once | S3 Object Lock, Azure immutable blob storage |
| Integrity validation is on | `aws cloudtrail validate-logs --trail-arn <arn> --start-time <iso8601>` |

```kql
SecurityEvent
| where EventID in (1102, 4719)
| project TimeGenerated, Computer, EventID, SubjectUserName, Activity
```

| Pass | Fail |
|------|------|
| Tampering is alerted and logs are immutable centrally | Admins can silently clear logs or stop trails |

---

**Mapping:** ISO 27001:2022 A.8.15, A.8.17 · NIST CSF 2.0 PR.PS-04, DE.CM · CIS v8 Control 8 · PCI DSS v4.0 Req. 10.2, 10.3, 10.5, 10.6 · CERT-In directions (28-Apr-2022)
