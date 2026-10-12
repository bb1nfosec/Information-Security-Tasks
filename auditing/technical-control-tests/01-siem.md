# Audit Tests — SIEM & Security Monitoring

> Is the SIEM receiving the right logs, keeping them long enough, detecting real attacks, and protected from tampering?

**Control objective:** Security-relevant events from all in-scope assets are collected centrally, retained per policy, analysed by maintained detection rules, and acted upon in a timely manner.

**Evidence to request up front**
- SIEM architecture diagram and list of integrated log sources
- Asset inventory / CMDB export for in-scope systems
- Logging & monitoring policy, retention standard
- Detection use-case register (rule name, owner, ATT&CK technique, last review date)
- SOC runbooks and incident tickets for the audit period
- Read-only SIEM role for the auditor

---

## SIEM-01 · Log source completeness

**Objective:** Every in-scope asset sends logs to the SIEM, and none has gone silent.

**Procedure**
1. Export the in-scope asset list from the CMDB (hostname, IP, criticality).
2. Pull the list of hosts that sent events in the last 30 days, with last-seen time.
3. Reconcile the two lists: assets missing from the SIEM, and sources silent for more than 24 h.

**Evidence — Splunk**
```spl
| tstats latest(_time) as last_seen count where index=* earliest=-30d by host
| eval hours_silent = round((now() - last_seen) / 3600, 1)
| eval last_seen = strftime(last_seen, "%Y-%m-%d %H:%M")
| sort - hours_silent
```

**Evidence — Microsoft Sentinel (KQL)**
```kql
// Agent-based sources
Heartbeat
| where TimeGenerated > ago(30d)
| summarize LastSeen = max(TimeGenerated) by Computer
| extend HoursSilent = datetime_diff('hour', now(), LastSeen)
| order by HoursSilent desc

// All tables: which data types are flowing at all
union withsource = TableName *
| where TimeGenerated > ago(7d)
| summarize Events = count(), LastEvent = max(TimeGenerated) by TableName
| order by LastEvent asc
```

**Reconcile (PowerShell)**
```powershell
$cmdb = Import-Csv .\cmdb_inscope.csv | ForEach-Object { $_.Hostname.ToLower() }
$siem = Import-Csv .\siem_hosts.csv   | ForEach-Object { $_.host.ToLower() }
$cmdb | Where-Object { $_ -notin $siem } | Set-Content .\missing_from_siem.txt
```

| Pass | Fail |
|------|------|
| 100% of critical assets, and ≥ 95% of all in-scope assets, report to the SIEM | Critical assets missing, or a large share of assets not reporting |
| Silent sources raise an alert and a ticket (see SIEM-06) | Sources silent for days with no ticket |

---

## SIEM-02 · Log retention

**Objective:** Logs are retained for the period required by policy and regulation.

**Procedure**
1. Get the required retention from policy and regulation. Common minimums: CERT-In 180 days (India); PCI DSS 12 months with 3 months immediately available.
2. Pull configured retention per index or table.
3. Verify by searching for the oldest event actually present.

**Evidence — Splunk**
```spl
| rest /services/data/indexes
| eval retention_days = round(frozenTimePeriodInSecs / 86400, 0)
| table title retention_days maxTotalDataSizeMB coldToFrozenDir
```
> Size limits (`maxTotalDataSizeMB`) can delete data before the time limit is reached. Always confirm with the oldest-event search:
```spl
| tstats earliest(_time) as oldest where index=* by index
| eval oldest = strftime(oldest, "%Y-%m-%d")
```

**Evidence — Sentinel / Log Analytics**
```bash
az monitor log-analytics workspace show -g <rg> -n <workspace> --query retentionInDays
az monitor log-analytics workspace table list -g <rg> --workspace-name <workspace> \
  --query "[].{table:name, interactiveDays:retentionInDays, totalDays:totalRetentionInDays}" -o table
```

| Pass | Fail |
|------|------|
| Configured and actual retention ≥ the required period for every in-scope source | Any in-scope source below requirement, or size caps that cut retention short |
| Archived logs are restorable (ask for a demo restore) | Archive exists but nobody has ever restored from it |

---

## SIEM-03 · Detection rule inventory & ATT&CK coverage

**Objective:** Detection rules exist for the organisation's priority threats, are enabled, and are reviewed periodically.

**Procedure**
1. Export all enabled scheduled or analytic rules.
2. Compare them to the use-case register: are there rules with no owner, or register entries with no rule?
3. Map rules to MITRE ATT&CK and load the layer into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to find gaps against the organisation's threat profile.
4. Check that the last-review date is within the review cycle (e.g. 12 months).

**Evidence — Splunk (and Splunk ES correlation searches)**
```spl
| rest /servicesNS/-/-/saved/searches
| search is_scheduled=1 disabled=0
| table title eai:acl.app cron_schedule actions action.correlationsearch.enabled updated
```

**Evidence — Sentinel**
Export analytics rules (Sentinel → Analytics → Export) or use the REST API `GET .../providers/Microsoft.SecurityInsights/alertRules`. Each rule's `tactics` and `techniques` fields give you the ATT&CK mapping.

**Minimum use cases to look for** (adapt to your threat profile)

| Use case | ATT&CK | Typical source |
|----------|--------|----------------|
| Brute force / password spray | T1110 | 4625, Entra sign-in logs |
| Privileged group membership change | T1098 | 4728, 4732, 4756 |
| Security log cleared | T1070.001 | 1102 |
| Encoded / suspicious PowerShell | T1059.001 | 4104, 4688 |
| New service / scheduled task | T1543.003, T1053.005 | 7045, 4698 |
| Kerberoasting | T1558.003 | 4769 (RC4, many SPNs) |
| Impossible travel / risky sign-in | T1078 | Entra ID Protection |
| EDR malware detection | — | EDR alerts |
| Mass file modification (ransomware) | T1486 | EDR, file-server audit |

| Pass | Fail |
|------|------|
| Each high-priority threat has at least one enabled, owned and reviewed rule | Key techniques have no coverage, or rules are disabled or orphaned |
| The use-case register matches the SIEM | The register is out of date with the system |

---

## SIEM-04 · Detection effectiveness (does it actually fire?)

**Objective:** Sampled rules detect the behaviour they claim to detect.

**Procedure**
1. Pick 3–5 high-priority rules from SIEM-03.
2. With **written approval and a change ticket**, have the blue team run a safe simulation on a test host. Use [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) or their breach-and-attack-simulation tool.
3. Confirm that an alert was created, routed to the queue, and triaged within the SLA.

**Evidence**
```powershell
# Atomic Red Team (run by the blue team, on an approved test host only)
Invoke-AtomicTest T1059.001 -ShowDetailsBrief      # list available tests first
Invoke-AtomicTest T1059.001 -TestNumbers <n>        # run the agreed test
Invoke-AtomicTest T1059.001 -TestNumbers <n> -Cleanup
```
Record: test time → alert time → ticket ID → analyst action.

**Non-invasive alternative:** if live testing isn't allowed, sample 5 true-positive incidents from the period. Trace each one from raw event, to alert, to ticket, to closure.

| Pass | Fail |
|------|------|
| Every sampled rule produced an alert that reached the SOC queue | Rule enabled but did not fire, or fired but nobody saw it |

---

## SIEM-05 · Alert triage & response timeliness

**Objective:** Alerts are investigated and closed within defined SLAs, and closures are justified.

**Procedure**
1. Get SOC SLAs by severity (e.g. Critical: acknowledge in 15 min, resolve in 4 h).
2. Pull all incidents for the period. Compute time to acknowledge, time to close, and the false-positive rate.
3. Sample closed incidents. Check that the closure reason is documented and that "false positive" verdicts are justified.

**Evidence — Sentinel**
```kql
SecurityIncident
| where CreatedTime > ago(90d)
| summarize arg_max(TimeGenerated, *) by IncidentNumber      // latest state of each incident
| extend MinutesToClose = datetime_diff('minute', ClosedTime, CreatedTime)
| summarize Total = count(),
            Open = countif(Status != "Closed"),
            FalsePositive = countif(Classification == "FalsePositive"),
            MedianMinutesToClose = percentile(MinutesToClose, 50),
            P90MinutesToClose = percentile(MinutesToClose, 90)
          by Severity
```

**Evidence — Splunk ES**
```spl
| `incident_review`
| stats count by urgency status_label owner
```
> Use the incident review export or `notable` index if the macro is unavailable in your version.

| Pass | Fail |
|------|------|
| ≥ 95% of incidents meet the SLA; sampled closures have documented reasoning | SLA breaches, or bulk closures with no notes |
| The FP rate is tracked and noisy rules are tuned | A very high FP rate with no tuning, so analysts suffer alert fatigue |

---

## SIEM-06 · Log source health monitoring

**Objective:** The SIEM alerts when a log source stops sending.

**Procedure**
1. Ask for the "source silent" rule and see it in the SIEM.
2. Check that it covers critical sources (DCs, firewalls, EDR, cloud audit logs).
3. Sample one silent source from SIEM-01. Was a ticket raised?

**Evidence — Sentinel (example rule logic)**
```kql
let threshold = 2h;
Heartbeat
| summarize LastSeen = max(TimeGenerated) by Computer
| where LastSeen < ago(threshold)
```

| Pass | Fail |
|------|------|
| An automated health alert exists and was acted upon in the sample | No health monitoring; gaps are found only during incidents |

---

## SIEM-07 · SIEM access & tamper protection

**Objective:** Only authorised people can administer the SIEM, delete data, or disable rules, and their actions are logged.

**Procedure**
1. Export SIEM users and roles. Reconcile them to HR (leavers) and to approved access requests.
2. Identify who can delete data or edit and disable rules.
3. Check that the SIEM's own audit log records rule changes, and sample changes against tickets.

**Evidence — Splunk**
```spl
| rest /services/authentication/users
| table title realname roles last_successful_login

| rest /services/authorization/roles
| search capabilities="delete_by_keyword" OR imported_capabilities="delete_by_keyword"
| table title capabilities imported_capabilities

index=_audit action=edit_search OR action=edit_saved_search OR action=delete_by_keyword
| table _time user action info object
```

**Evidence — Sentinel**
```bash
az role assignment list --scope <workspace-resource-id> --include-inherited -o table
```
```kql
AzureActivity
| where OperationNameValue has "Microsoft.SecurityInsights/alertRules"
| project TimeGenerated, Caller, OperationNameValue, ActivityStatusValue
```

| Pass | Fail |
|------|------|
| Delete and admin rights are limited to named SIEM admins; no leavers remain; rule changes trace to tickets | Broad admin rights, shared accounts, or unlogged rule changes |

---

## SIEM-08 · Time synchronisation of sources

**Objective:** Event timestamps are reliable, so events can be correlated.

**Procedure:** Compare event time with index or ingest time. Large or negative gaps suggest clock skew or ingestion delay. See also [LOG-06](05-logging-coverage.md#log-06--time-synchronisation).

```spl
index=* earliest=-24h
| eval lag_sec = _indextime - _time
| stats median(lag_sec) as median_lag max(lag_sec) as max_lag by host sourcetype
| where median_lag > 300 OR median_lag < -60
```
```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| extend LagSec = datetime_diff('second', ingestion_time(), TimeGenerated)
| summarize MedianLag = percentile(LagSec, 50), MaxLag = max(LagSec) by Computer
| where MedianLag > 300 or MedianLag < -60
```

| Pass | Fail |
|------|------|
| Median lag of a few minutes or less; no negative lag (events "from the future") | Hosts with large skew or delay that affects correlation and SLAs |

---

**Mapping:** ISO 27001:2022 A.8.15, A.8.16, A.8.17 · NIST CSF 2.0 DE.CM, DE.AE · CIS v8 Control 8, 13 · PCI DSS v4.0 Req. 10
