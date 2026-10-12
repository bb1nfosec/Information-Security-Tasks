# Compliance & Risk Assessment

> Security frameworks, standards, and risk management — ISO 27001, NIST, PCI-DSS, SOC 2, GDPR.

---

## Framework Overview

| Framework | Scope | Type |
|-----------|-------|------|
| ISO 27001 | ISMS — Information Security Management | Certifiable standard |
| NIST CSF | Cybersecurity risk management | Voluntary framework |
| NIST 800-53 | US federal systems controls | Control catalog |
| PCI DSS | Payment card data | Compliance standard |
| SOC 2 | Service organization security | Audit report |
| GDPR | EU personal data | Regulation (legal) |
| HIPAA | US health data | Regulation (legal) |
| CIS Controls | Technical security controls | Best practice |

---

## ISO 27001

```
Annex A has 93 controls across 4 themes (ISO 27001:2022):
  5.x  Organizational controls (37)
  6.x  People controls (8)
  7.x  Physical controls (14)
  8.x  Technological controls (34)

Key documents needed:
  □ Information Security Policy
  □ Risk Assessment & Treatment Plan
  □ Statement of Applicability (SoA)
  □ Risk Register
  □ Asset Inventory
  □ Access Control Policy
  □ Incident Response Procedure
  □ Business Continuity Plan
```

---

## NIST CSF 2.0 Functions

```
GOVERN  → Policies, roles, risk strategy, supply chain
IDENTIFY → Assets, risks, vulnerabilities
PROTECT → Access control, awareness, data security
DETECT  → Continuous monitoring, anomaly detection
RESPOND → Incident response, communications
RECOVER → Recovery planning, lessons learned
```

---

## Risk Assessment (NIST SP 800-30)

```
Risk = Likelihood × Impact

Likelihood tiers:
  1 = Very Low (rare)
  2 = Low
  3 = Moderate
  4 = High
  5 = Very High (near certainty)

Impact tiers:
  1 = Very Low (minimal effect)
  2 = Low
  3 = Moderate
  4 = High
  5 = Very High (catastrophic)

Risk score = L × I  (1–25)
  1–5   = Low risk → accept or monitor
  6–12  = Medium risk → mitigate
  13–25 = High risk → immediate action
```

---

## PCI DSS v4.0 — 12 Requirements

| # | Requirement |
|---|-------------|
| 1 | Install and maintain network security controls |
| 2 | Apply secure configurations |
| 3 | Protect stored account data |
| 4 | Protect cardholder data in transit (TLS 1.2+) |
| 5 | Protect all systems against malware |
| 6 | Develop and maintain secure systems (patching) |
| 7 | Restrict access by business need |
| 8 | Identify users and authenticate access (MFA required) |
| 9 | Restrict physical access to cardholder data |
| 10 | Log and monitor all access |
| 11 | Test security regularly (pentest, ASV scan) |
| 12 | Support information security with policies |

---

## GDPR Key Articles for Security

| Article | Requirement |
|---------|-------------|
| Art. 25 | Privacy by design & default |
| Art. 32 | Technical measures: encryption, pseudonymization, resilience |
| Art. 33 | Breach notification to DPA within **72 hours** |
| Art. 34 | Notify individuals if high risk to their rights |
| Art. 35 | DPIA required for high-risk processing |

---

## CIS Controls v8 (Top 5 — 85% of attacks addressed)

1. **Inventory of Enterprise Assets** — know what you have
2. **Inventory of Software Assets** — no shadow IT
3. **Data Protection** — DLP, encryption, classification
4. **Secure Configuration** — harden every asset
5. **Account Management** — least privilege, MFA, offboarding

---

## Audit / Assessment Checklist

```
□ Asset inventory complete and current?
□ Data classification scheme in place?
□ Access reviews conducted (quarterly)?
□ Vulnerability scans run (at least monthly)?
□ Penetration test completed (annual)?
□ Incident response plan tested (tabletop exercise)?
□ Backup tested and recovery time documented?
□ Vendor/third-party risk assessments done?
□ Security awareness training completed (all staff)?
□ Patch management SLA defined and met?
```

For detailed test steps, evidence commands and pass/fail criteria, see **[Audit Test Procedures — Technical Controls](../auditing/technical-control-tests/README.md)**. It covers SIEM, firewall rule review, privileged access, backup and DR, and logging coverage, plus the [Windows Audit Policy Baseline](../auditing/windows-audit-policy-baseline.md).

---

## Tools

| Tool | Purpose |
|------|---------|
| [OpenRMF](https://github.com/Cingulara/openrmf-oss) | STIG compliance management |
| [OpenSCAP](https://www.open-scap.org) | NIST SCAP compliance scanning |
| [MISP](https://www.misp-project.org) | Threat intel sharing / ISO 27035 |
| [Vanta](https://www.vanta.com) | SOC 2 / ISO 27001 automation |
| [Drata](https://drata.com) | Continuous compliance monitoring |
