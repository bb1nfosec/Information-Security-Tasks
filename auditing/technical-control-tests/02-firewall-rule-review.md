# Audit Tests — Firewall Rule Review (Network Security Controls)

> Are firewall rules justified, least-privilege, logged, reviewed, and changed only through approved change management?

**Control objective:** Network traffic between trust zones is restricted to what is documented and business-justified, and firewall configurations are protected, reviewed and changed under control.

**Evidence to request up front**
- Network diagram showing zones (Internet, DMZ, internal, CDE/critical, management)
- Firewall standard: allowed services, prohibited protocols, review frequency
- Full configuration export for each in-scope firewall, extracted while you watch
- Rule-hit counts for the review period
- Firewall change tickets for the period, plus the device's config-change log
- Evidence of the last periodic rule review

---

## FW-01 · Obtain complete, reliable configuration

**Objective:** You are testing the real running configuration, not a document.

**Procedure:** Watch the admin export the running config from the device or manager, then hash it immediately.

| Platform | Command |
|----------|---------|
| Palo Alto (CLI) | `set cli config-output-format set` then `show config running` |
| Palo Alto (Panorama) | Export device-group / template configs, or use the XML API `type=config&action=show` |
| FortiGate | `show firewall policy` · `show firewall address` · `show firewall service custom` |
| Cisco ASA | `show running-config` · `show access-list` (includes hit counts) |
| Cisco FTD / FMC | Export the Access Control Policy from FMC (Policies → Export) |
| Linux | `iptables-save` · `ip6tables-save` · `nft list ruleset` |
| AWS | `aws ec2 describe-security-groups --output json > sg.json` |
| Azure | `az network nsg list -o json > nsg.json` |

```bash
sha256sum fw01_running.txt > fw01_running.sha256
```

| Pass | Fail |
|------|------|
| A complete export, observed and hashed, covering every in-scope device | Partial screenshots, or a config supplied by email with no provenance |

---

## FW-02 · Overly permissive rules ("any" rules)

**Objective:** No rule allows `any` source, destination **and** service, and no inbound rule from the internet is broader than needed.

**Procedure:** Filter the rule base for `any` in the source, destination or service fields, and for internet-sourced rules to internal zones.

**Evidence — quick filters**
```bash
# Palo Alto "set" format
grep -E "source any|destination any|service any|application any" fw01_running.txt

# Cisco ASA
grep -E "permit (ip|tcp|udp) any any" fw01_running.txt

# iptables: ACCEPT rules with no source restriction
iptables-save | grep -- "-j ACCEPT" | grep -v -- "-s "
```

**Evidence — cloud**
```bash
# AWS: security groups open to the whole internet
aws ec2 describe-security-groups \
  --query "SecurityGroups[?IpPermissions[?IpRanges[?CidrIp=='0.0.0.0/0']]].[GroupId,GroupName,VpcId]" \
  --output table

# Azure: inbound Allow rules from anywhere
az network nsg list --query "[].{nsg:name, rules:securityRules[?direction=='Inbound' && access=='Allow' && (sourceAddressPrefix=='*' || sourceAddressPrefix=='Internet' || sourceAddressPrefix=='0.0.0.0/0')].{rule:name, port:destinationPortRange}}" -o json
```

| Pass | Fail |
|------|------|
| No any/any/any allow rules; every broad rule has a documented, approved justification | Any/any rules, or internet-to-internal rules with no justification |

---

## FW-03 · Insecure and high-risk services

**Objective:** Risky protocols are not allowed, especially from untrusted zones.

**Look for allow rules on:**

| Port | Service | Concern |
|------|---------|---------|
| 21 | FTP | Cleartext credentials |
| 23 | Telnet | Cleartext admin access |
| 69 | TFTP | No authentication |
| 135, 139, 445 | RPC / NetBIOS / SMB | Lateral movement, ransomware spread; never from the internet |
| 161 | SNMP v1/v2c | Community strings in clear text |
| 389 | LDAP (unsigned) | Credential exposure |
| 1433, 3306, 5432, 1521 | Databases | Should never be internet-facing |
| 3389 | RDP | Top initial-access vector; never from the internet |
| 5900 | VNC | Weak authentication |
| 22 from internet | SSH | Acceptable only via a bastion or VPN with MFA and source restriction |

```bash
grep -E "(port|service|destination-port)[^0-9]*(21|23|69|135|139|445|161|1433|3306|3389|5432|5900)\b" fw01_running.txt
```

| Pass | Fail |
|------|------|
| None allowed from untrusted zones; any internal use is justified and compensated (e.g. SNMPv3) | Internet-facing RDP, SMB, Telnet or database ports |

---

## FW-04 · Unused, shadowed and redundant rules

**Objective:** The rule base contains no dead rules that hide risk or confuse reviewers.

**Procedure**
1. Pull hit counts for the full review period. Rules with **zero hits in 90+ days** are candidates for removal.
2. Identify shadowed rules (never reachable because an earlier rule matches first) and duplicates. Use an analyser for this: Nipper, Tufin, AlgoSec, FireMon, or the open-source [Batfish](https://github.com/batfish/batfish).

**Evidence**
```bash
# Palo Alto
show rule-hit-count vsys vsys-name vsys1 rule-base security rules all

# Cisco ASA (hitcnt=0)
show access-list | include hitcnt=0
```
> Confirm when counters were last reset. A reboot or upgrade resets them, so "0 hits" over a short window proves nothing.

| Pass | Fail |
|------|------|
| Unused rules are reviewed and either removed or justified | Many zero-hit or shadowed rules with no action |

---

## FW-05 · Rule documentation & ownership

**Objective:** Every rule can be traced to a business owner, purpose and approval.

**Procedure:** Sample 25 rules, weighted toward internet-facing and critical-zone rules. Each rule should have a description or tag with a ticket ID, owner and purpose, and an expiry date if it is temporary.

```bash
# Palo Alto: rules missing a description
grep -E "^set rulebase security rules" fw01_running.txt | awk '{print $5}' | sort -u > all_rules.txt
grep -E "^set rulebase security rules .* description" fw01_running.txt | awk '{print $5}' | sort -u > described.txt
comm -23 all_rules.txt described.txt
```
> In `set` format, rule names containing spaces are quoted, so adjust the field if needed.

| Pass | Fail |
|------|------|
| All sampled rules trace to an approved request; temporary rules have expired or been removed | Undocumented rules, "temp" rules years old |

---

## FW-06 · Default deny & logging

**Objective:** Traffic not explicitly allowed is denied, and allow/deny decisions are logged to the SIEM.

**Procedure**
1. Confirm the last rule is an explicit deny-all with logging enabled. Implicit denies often do not log by default; Palo Alto's `interzone-default`, for example, does not log unless you override it.
2. Check that logging is enabled on allow rules, especially rules to and from critical zones.
3. Confirm firewall logs are in the SIEM (see [SIEM-01](01-siem.md)).

```bash
# Palo Alto: rules with logging at session end disabled
grep -E "log-end no" fw01_running.txt
# FortiGate: policies with logging disabled
grep -B20 "set logtraffic disable" fw01_running.txt | grep "edit"
```

| Pass | Fail |
|------|------|
| Explicit, logged deny-all; allow rules log; logs reach the SIEM | No default deny, or blind spots where logging is off |

---

## FW-07 · Change management

**Objective:** Every rule change during the period was requested, risk-assessed, approved, implemented as approved, and verified.

**Procedure**
1. Get the **population of changes from the device**, not from the ticketing tool: the config audit log or a diff of monthly config backups.
2. Sample changes and match each one to a ticket. Check that the approver is not the implementer, the approval came before implementation, and what was implemented matches what was approved.
3. Check emergency changes for retrospective approval.

```bash
# Palo Alto config log
show log config start-time equal 2026/04/01@00:00:00

# Diff two config backups to find undocumented changes
diff <(sort fw01_2026-06-30.txt) <(sort fw01_2026-09-30.txt)
```

| Pass | Fail |
|------|------|
| 100% of sampled changes are approved before implementation, with segregation of duties | Changes with no ticket, self-approved, or approved after the fact without an emergency process |

---

## FW-08 · Periodic rule-base review

**Objective:** The full rule base is reviewed on schedule. PCI DSS v4.0 req. 1.2.7 requires a review at least once every six months.

**Procedure:** Ask for the last two reviews. Check the scope (all devices), the reviewer, the date, the rules flagged, and that remediation was completed.

| Pass | Fail |
|------|------|
| Reviews were done on time, covered all devices, and flagged rules were removed or justified | No review, a rubber-stamp sign-off, or flagged rules never actioned |

---

## FW-09 · Firewall administration security

**Objective:** The firewalls themselves are hardened.

| Check | Evidence |
|-------|----------|
| Management interface reachable only from a management network or jump host | Management interface profile or permitted IPs in the config |
| Named admin accounts through TACACS+/RADIUS with MFA; no shared `admin` account in use | Admin list, authentication profile, login logs |
| Firmware is vendor-supported and patched for critical CVEs | Version output (`show system info`, `get system status`, `show version`) compared with vendor advisories |
| Config backups scheduled and stored off-device | Backup job evidence |
| Admin activity logged to the SIEM | SIEM search for firewall admin logins and config commits |

---

**Mapping:** ISO 27001:2022 A.8.20, A.8.21, A.8.22, A.8.32 · NIST CSF 2.0 PR.IR-01, PR.PS-01 · CIS v8 Controls 4, 12, 13 · PCI DSS v4.0 Req. 1
