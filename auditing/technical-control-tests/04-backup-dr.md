# Audit Tests — Backup, Restore & Disaster Recovery

> A backup that has never been restored is a hope, not a control. Ransomware operators target backups first.

**Control objective:** Critical data and systems are backed up according to defined RPO/RTO, backups are protected from tampering and deletion, restores are tested and succeed within the RTO, and DR plans are maintained and exercised.

**Evidence to request up front**
- Backup policy and standard (frequency, retention, copies, encryption, immutability)
- Business impact analysis (BIA), with RPO and RTO per critical system
- Backup tool job reports for the period (Veeam, Commvault, Rubrik, Azure Backup, AWS Backup, etc.)
- Restore test records and DR test reports for the last 12 months
- The DR / business continuity plan and its approval history
- The list of users and roles with admin rights on the backup platform

---

## BKP-01 · Backup coverage against critical systems

**Objective:** Every system the BIA calls critical is in a backup job, at a frequency that meets its RPO.

**Procedure**
1. List critical systems with their RPO from the BIA.
2. Export all backup jobs and the objects protected in each.
3. Reconcile: critical systems not protected at all, and systems whose job frequency is longer than the RPO (e.g. a daily job against a 4-hour RPO).

**Evidence — Veeam (PowerShell on the backup server)**
```powershell
Get-VBRJob | ForEach-Object {
  $job = $_
  $job.GetObjectsInJob() | Select-Object @{n='Job';e={$job.Name}}, Name,
    @{n='Schedule';e={$job.ScheduleOptions}}
} | Export-Csv .\veeam_job_objects.csv -NoTypeInformation
```
> Newer Veeam versions are moving to `Get-VBRComputerBackupJob` and related cmdlets for agent jobs. Use whichever lists the protected objects in your version.

**Evidence — Azure Backup**
```bash
az backup item list -g <rg> --vault-name <vault> \
  --query "[].{item:properties.friendlyName, type:properties.workloadType, policy:properties.policyName, lastBackup:properties.lastBackupTime, status:properties.lastBackupStatus}" -o table
```

**Evidence — AWS Backup**
```bash
aws backup list-protected-resources \
  --query "Results[].{arn:ResourceArn,type:ResourceType,last:LastBackupTime}" --output table
```

| Pass | Fail |
|------|------|
| 100% of critical systems protected, at a frequency that meets their RPO | Critical systems missing, or backup frequency weaker than the RPO |

---

## BKP-02 · Backup job success & failure handling

**Objective:** Backups complete successfully, and failures are detected and fixed promptly.

**Evidence — Veeam (last 30 days)**
```powershell
Get-VBRBackupSession |
  Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-30) } |
  Group-Object Result | Select-Object Name, Count

# Detail of failures
Get-VBRBackupSession |
  Where-Object { $_.CreationTime -gt (Get-Date).AddDays(-30) -and $_.Result -eq 'Failed' } |
  Select-Object JobName, CreationTime, EndTime, Result
```

**Evidence — AWS Backup**
```bash
aws backup list-backup-jobs --by-state FAILED --by-created-after 2026-09-01T00:00:00Z \
  --query "BackupJobs[].{resource:ResourceArn,created:CreationDate,msg:StatusMessage}" --output table
```

**Evidence — Azure Backup**
```bash
az backup job list -g <rg> --vault-name <vault> --status Failed -o table
```

**Procedure:** Sample failed jobs and check for:
- an alert or ticket raised
- a root cause recorded
- a successful re-run inside the RPO window
- systems failing repeatedly (e.g. 3 or more consecutive failures) that nobody escalated

| Pass | Fail |
|------|------|
| Success rate ≥ policy target (e.g. 98%); every failure ticketed and resolved within RPO | Silent failures, or the same job failing for days |

---

## BKP-03 · Backup protection: immutability, isolation & encryption

**Objective:** Backups survive a ransomware attacker who holds domain admin, following the 3-2-1-1-0 rule. That means 3 copies, on 2 media, 1 offsite, 1 immutable or offline, and 0 errors on restore verification.

| Check | Evidence |
|-------|----------|
| At least one copy is immutable or air-gapped | Veeam hardened Linux repository, or object-lock settings, see below |
| Backup server is **not** joined to the production domain, or sits in a separate tier/forest | `systeminfo \| findstr /i domain` on the backup server |
| Backup console admin requires MFA and separate credentials | Authentication config, admin list |
| Backups encrypted at rest and in transit | Job encryption settings, KMS key policy |
| Deletion or retention change needs 4-eyes approval, or soft delete is enabled | Platform settings |
| Offsite or different-region copy exists | Copy job, or cross-region replication config |

**Evidence — immutability**
```bash
# AWS S3 Object Lock on the backup bucket
aws s3api get-object-lock-configuration --bucket <backup-bucket>

# AWS Backup Vault Lock
aws backup describe-backup-vault --backup-vault-name <vault> \
  --query "{locked:Locked, minDays:MinRetentionDays, maxDays:MaxRetentionDays}"

# Azure Recovery Services vault: soft delete & immutability
az backup vault backup-properties show -g <rg> -n <vault> -o json
az backup vault show -g <rg> -n <vault> --query "properties.securitySettings" -o json
```

| Pass | Fail |
|------|------|
| An immutable or offline copy exists; backup admin is separated from the domain; MFA in place | Every copy is deletable by a domain admin; backup server joined to the domain with shared credentials |

---

## BKP-04 · Restore testing (the most important test)

**Objective:** Backups can actually be restored, completely and within RTO.

**Procedure**
1. Get the restore test log for the period. Check frequency against policy, and whether the tests covered critical systems or only random files.
2. **Witness a restore yourself.** Pick a critical system or dataset and have it restored to an isolated location. Record the start and end time.
3. Verify integrity: compare hashes or record counts with production at the backup point, and have the business owner confirm the data is usable.
4. Compare the actual restore duration with the RTO.

**Evidence**
```powershell
# Windows: hash files in the restored folder and in a known-good reference
Get-ChildItem -Recurse .\restored | Get-FileHash -Algorithm SHA256 | Export-Csv restored_hashes.csv -NoTypeInformation
```
```bash
# Linux
find /restore/path -type f -exec sha256sum {} + | sort -k2 > restored.sha256
diff <(sort -k2 reference.sha256) restored.sha256
```
```sql
-- Database: compare row counts for key tables at the backup point
SELECT 'customers' AS tbl, COUNT(*) FROM customers
UNION ALL SELECT 'transactions', COUNT(*) FROM transactions;
```

| Pass | Fail |
|------|------|
| Restores are tested on schedule, including critical systems; the witnessed restore succeeded within RTO and data was verified | No restore testing, only small files tested, or the restore failed or exceeded RTO |

---

## BKP-05 · Retention

**Objective:** Backups are kept for the required periods (business, legal, regulatory) and not much longer, which would create a privacy risk under DPDP and GDPR data-minimisation rules.

**Procedure:** Compare the retention configured in policies or jobs with the retention schedule. Then check that the oldest restore point actually available matches.

```powershell
# Veeam: oldest restore point per backup
Get-VBRBackup | ForEach-Object {
  $rp = Get-VBRRestorePoint -Backup $_ | Sort-Object CreationTime | Select-Object -First 1
  [pscustomobject]@{ Backup = $_.Name; OldestRestorePoint = $rp.CreationTime }
}
```

| Pass | Fail |
|------|------|
| Configured and actual retention match the schedule | Retention shorter than legal requirements, or kept indefinitely with no basis |

---

## BKP-06 · Backup platform access

**Objective:** Only authorised backup administrators can change jobs, retention, or delete backups.

**Procedure:** Export the backup platform users and roles. Reconcile them with approved access and the HR leaver list. Check the platform audit log for deletions and retention changes, and match each to a ticket.

```bash
# Azure: who has rights on the vault
az role assignment list --scope <vault-resource-id> --include-inherited -o table
```

| Pass | Fail |
|------|------|
| A small, named admin group; deletions approved | Broad access; untraced deletions |

---

## DR-01 · DR plan currency

**Objective:** A DR plan exists for critical services, is approved, and reflects the current environment.

| Check | Pass criterion |
|-------|----------------|
| Plan covers every critical service in the BIA | Yes, with RTO/RPO per service |
| Reviewed and approved within the last 12 months | Dated sign-off |
| Contacts, call trees and vendor contacts are current | Sample 3 names against HR |
| Recovery runbooks are step-by-step and reference the current infrastructure (cloud, new apps) | No references to decommissioned systems |
| Includes a cyber scenario (ransomware: restore from clean, immutable backups) | Not just site or power loss |

---

## DR-02 · DR testing

**Objective:** DR capability is proven by exercises, and lessons are acted on.

**Procedure**
1. Get the DR test reports for the last 12 months. Note the type of each: tabletop, partial failover, or full failover.
2. Compare the achieved RTO/RPO with the targets.
3. Trace every issue raised in the test report to a remediation action and confirm it closed.

| Pass | Fail |
|------|------|
| At least an annual test of critical services, targets met or gaps remediated | No test, a test with no report, or repeated failures with no action |

---

**Mapping:** ISO 27001:2022 A.8.13, A.8.14, A.5.29, A.5.30 · NIST CSF 2.0 PR.DS-11, RC.RP · CIS v8 Control 11 · PCI DSS v4.0 Req. 12.10.1 (business recovery and continuity in the IR plan)
