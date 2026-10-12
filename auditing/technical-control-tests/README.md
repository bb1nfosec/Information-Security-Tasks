# Audit Test Procedures — Technical Security Controls

> Practical audit work programs for IT auditors, GRC analysts and blue teamers. Each test gives the objective, the procedure, the command or query to pull evidence, and the pass/fail criteria.

The goal is to bridge two worlds: auditors who know *what* a control should achieve, and defenders who know *where* the evidence lives. Every test here produces evidence you can re-perform, not screenshots of a dashboard.

---

## Work programs

| File | Control area | Typical evidence sources |
|------|--------------|--------------------------|
| [01-siem.md](01-siem.md) | SIEM & security monitoring | Splunk, Microsoft Sentinel, Elastic |
| [02-firewall-rule-review.md](02-firewall-rule-review.md) | Network security controls (NSC) | Palo Alto, FortiGate, Cisco ASA, iptables/nftables, AWS SG, Azure NSG |
| [03-privileged-access.md](03-privileged-access.md) | Privileged access management (PAM) | Active Directory, Entra ID, Linux sudo, PAM vault |
| [04-backup-dr.md](04-backup-dr.md) | Backup, restore & disaster recovery | Veeam, Azure Backup, AWS Backup, DR plan |
| [05-logging-coverage.md](05-logging-coverage.md) | Log generation, collection & retention | Windows, Linux, CloudTrail, M365, NTP |
| [../windows-audit-policy-baseline.md](../windows-audit-policy-baseline.md) | Windows advanced audit policy baseline | `auditpol`, GPO, registry |

---

## How to use these procedures

```
1. SCOPE      Agree in-scope systems, period under review, and the control owner
    │
    ▼
2. DESIGN     Does the control, as documented, address the risk?
    │          (policy, standard, procedure, configuration standard)
    ▼
3. EVIDENCE   Pull evidence yourself or observe the admin pulling it
    │
    ▼
4. TEST       Run the test steps; compare result against pass/fail criteria
    │
    ▼
5. CONCLUDE   Effective / Partially effective / Ineffective → write findings
```

**Test of design (ToD)** asks whether the control *can* work. **Test of operating effectiveness (ToE)** asks whether it *did* work across the whole audit period. Most tests below are ToE; run ToD first, because a control that is badly designed does not need a sample test.

---

## Evidence handling rules

| Rule | Why |
|------|-----|
| Observe the extraction live (screen share is fine) or run the query yourself with read-only access | Prevents edited or filtered exports |
| Capture the command, the timestamp and the system name with the output | Makes the test re-performable |
| Hash exported files: `Get-FileHash file.csv -Algorithm SHA256` / `sha256sum file.csv` | Proves evidence was not changed after collection |
| Prefer full populations from systems over lists maintained by the auditee | Spreadsheets drift from reality |
| Request read-only roles, never admin accounts | Auditors must not be able to change what they audit |
| Store evidence in the audit file with a reference ID (e.g. `EV-SIEM-01-a`) | Every finding must trace back to evidence |

### Sampling guide (operating effectiveness)

| Control frequency | Population (per year) | Suggested sample |
|-------------------|-----------------------|------------------|
| Annual | 1 | 1 |
| Quarterly | 4 | 2 |
| Monthly | 12 | 2–5 |
| Weekly | 52 | 5–15 |
| Daily | 365 | 20–40 |
| Many times a day / automated | 365+ | 25–60, or test the automated config once plus change control |

Adjust sample sizes to your firm's methodology and the assessed risk. For automated controls, testing the configuration once plus showing that the configuration did not change during the period (via change management) is usually enough.

---

## Finding write-up template

Use the **5 Cs** so findings are actionable:

```
ID:             SIEM-01-F1
Title:          12% of in-scope servers not sending logs to SIEM
Rating:         High / Medium / Low

Condition:      What you found (facts, numbers, evidence ref)
                 "38 of 312 in-scope Windows servers (12%) had no events in the
                  SIEM in the 30 days to 30-Sep-2026. (EV-SIEM-01-a)"
Criteria:       What should be (policy clause, standard, regulation)
                 "Logging Standard §4.2; ISO 27001:2022 A.8.15; CERT-In
                  directions 28-Apr-2022 (log retention 180 days)"
Cause:          Why it happened (root cause, not symptom)
                 "No automated check reconciles CMDB to SIEM sources;
                  new servers are onboarded by manual ticket."
Consequence:    Risk / impact if not fixed
                 "Attacks on these servers would not be detected, and
                  investigations would lack evidence."
Corrective action: Specific, owned, dated recommendation
                 "Build a daily CMDB-vs-SIEM reconciliation with alerting;
                  owner: SOC Lead; target: 31-Dec-2026."
```

---

## Framework mapping

| Area | ISO 27001:2022 Annex A | NIST CSF 2.0 | CIS Controls v8 | PCI DSS v4.0 |
|------|------------------------|--------------|-----------------|--------------|
| SIEM & monitoring | 8.15, 8.16 | DE.CM, DE.AE | 8, 13 | 10.4, 10.7 |
| Firewall rules | 8.20, 8.21, 8.22, 8.32 | PR.IR-01, PR.PS-01 | 4, 12, 13 | 1.2, 1.3, 1.4 |
| Privileged access | 5.15, 5.18, 8.2, 8.5 | PR.AA-01, PR.AA-05 | 5, 6 | 7.2, 8.2, 8.4, 8.6 |
| Backup & DR | 8.13, 8.14, 5.29, 5.30 | PR.DS-11, RC.RP | 11 | 12.10.1 (IR/BCP) |
| Logging coverage | 8.15, 8.17 | PR.PS-04, DE.CM | 8 | 10.2, 10.5, 10.6 |

**India-specific:** the CERT-In directions under Section 70B of the IT Act (28 April 2022) require ICT system logs to be retained for 180 days within Indian jurisdiction, clocks to be synchronised to NIC/NPL NTP servers (or servers traceable to them), and reportable incidents to be reported within 6 hours. Check sector rules too: RBI (banks and NBFCs), SEBI CSCRF (regulated entities), IRDAI (insurers).

> Framework clause numbers change between versions. Confirm against the version your organisation is certified to or assessed against.

---

## Contributing

Add a new control area as `0N-<area>.md` following the same structure: **ID → Objective → Procedure → Evidence command → Pass / Fail**. Platform-specific queries for tools not covered here (QRadar, Chronicle, Check Point, CyberArk, Commvault...) are very welcome.
