# Information Security Tasks

> Real-world infosec notes, methodologies, and daily resources — contributed by practitioners, for practitioners.

[![Stars](https://img.shields.io/github/stars/bb1nfosec/Information-Security-Tasks?style=flat-square)](https://github.com/bb1nfosec/Information-Security-Tasks/stargazers)
[![Daily Feed](https://img.shields.io/badge/updated-daily-16a34a?style=flat-square)](feeds/)
[![Submit](https://img.shields.io/badge/submit%20a%20resource-7c3aed?style=flat-square)](https://github.com/bb1nfosec/Information-Security-Tasks/issues/new?template=submit-resource.yml)
[![Site](https://img.shields.io/badge/infosec--gym-live-0d1117?style=flat-square&logo=github)](https://bb1nfosec.github.io/Information-Security-Tasks)

Knowledge should be free, accessible to all, and in one place.

---

## AI & Emerging Threats

| Directory | Contents |
|-----------|----------|
| [ai-agents/](ai-agents/) | Agent hijacking, indirect injection, tool poisoning, MCP attacks, memory poisoning, multi-agent lateral movement |
| [ai-security/](ai-security/) | LLM attacks, jailbreaking, data poisoning, model extraction, OWASP LLM Top 10 |
| [ics-security/](ics-security/) | SCADA/PLC attacks, Modbus/DNP3/EtherNet-IP exploitation, critical infrastructure incidents |

---

## Offensive Security

| Directory | Contents |
|-----------|----------|
| [active-directory/](active-directory/) | AD attack paths, enumeration, LAPS/PAM abuse |
| [enumeration/](enumeration/) | Port-by-port enumeration (SSH, SMB, DNS, LDAP, HTTP...) |
| [pentest/](pentest/) | Methodology, tools reference, checklists |
| [privilege-escalation/](privilege-escalation/) | Linux & Windows escalation techniques |
| [post-exploitation/](post-exploitation/) | File transfer, pivoting, tunnelling |
| [red-teaming/](red-teaming/) | TTPs, Cobalt Strike C2, AV bypass, covert infra |
| [web-hacking/](web-hacking/) | SQLi, XSS, SSRF, SSTI, IDOR, JWT, CORS, command injection |
| [android-hacking/](android-hacking/) | Frida, objection, SSL pinning bypass, GDB remote debug |
| [mobile/](mobile/) | iOS hacking, mobile application testing |
| [cloud-hacking/](cloud-hacking/) | AWS, GCP, Azure attack surface |
| [exploitation/](exploitation/) | x86 exploitation, CPU internals, virtual memory |
| [reverse-engineering/](reverse-engineering/) | ELF, crackmes, disassembly, x86 architecture |
| [malware/](malware/) | Shellcode execution, process injection, maldev-reloaded |
| [covert-infrastructure/](covert-infrastructure/) | VPN setup, covert C2 infrastructure |
| [wi-fi-hacking/](wi-fi-hacking/) | WEP/WPA attacks |
| [radio-frequency/](radio-frequency/) | RF hacking techniques |
| [hardware-hacking/](hardware-hacking/) | Firmware extraction, hardware exploits |
| [macos-hacking/](macos-hacking/) | macOS security research |

## Defensive Security

| Directory | Contents |
|-----------|----------|
| [soc/](soc/) | SOC analyst notes, detection |
| [incident-response/](incident-response/) | IR playbooks |
| [forensics/](forensics/) | Digital & network forensics |
| [threat-hunting/](threat-hunting/) | Threat hunting techniques |
| [auditing/](auditing/) | Windows auditing mindmap, audit policy baseline, technical control audit tests (SIEM, firewall, PAM, backup/DR, logging) |
| [compliance/](compliance/) | Risk assessment frameworks |
| [vulnerability-analysis/](vulnerability-analysis/) | Vulnerability research notes |

## Reference & Skills

| Directory | Contents |
|-----------|----------|
| [osint/](osint/) | OSINT collection techniques |
| [cryptography/](cryptography/) | Theory, LFSR, applied crypto |
| [steganography/](steganography/) | Steg techniques |
| [programming/](programming/) | C, C++, Python, Nim, Assembly, algorithms |
| [linux/](linux/) | Linux commands, troubleshooting |
| [thin-client-testing/](thin-client-testing/) | Thin client & kiosk testing |
| [resources/](resources/) | Community-submitted links by category |
| [feeds/](feeds/) | Auto-generated daily: news + CVEs + tools |

---

## Daily auto-updates

A GitHub Action runs at **06:00 UTC** every day and commits a digest to `feeds/YYYY-MM-DD.md`:
- Security news — SANS ISC, The Hacker News, Schneier on Security, PortSwigger Research
- Critical CVEs from NVD
- New tool releases — KitPloit, GitHub trending security repos

---

## Submit a resource

[→ Open a resource submission issue](https://github.com/bb1nfosec/Information-Security-Tasks/issues/new?template=submit-resource.yml)

Fill in the form — the bot reads it, appends your link to the right category file under `resources/`, and closes the issue automatically.

---

## Token-optimized for LLM sessions

Scanned and optimized with [`distill-llm`](https://github.com/bb1nfosec/Distill):

```
Before  2.9M tokens  $8.84/session  (1473% of Claude context)
After    176k tokens  $0.53/session  (88% of context)
```

```sh
pip install distill-llm && distill scan --path .
```

---

## License

MIT — use it, share it, improve it.
