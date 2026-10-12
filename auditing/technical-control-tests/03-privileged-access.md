# Audit Tests — Privileged Access Management (PAM)

> Who holds the keys to the kingdom, should they, and is every use of those keys controlled and recorded?

**Control objective:** Privileged access is granted on a least-privilege and need-to-know basis, assigned to named individuals, protected with strong authentication, recorded, reviewed periodically, and removed promptly.

**Evidence to request up front**
- Privileged access policy / admin account standard
- PAM tool (CyberArk, BeyondTrust, Delinea, etc.): onboarded account list, rotation and session-recording settings
- HR joiner/mover/leaver list for the period
- The last two privileged access reviews, with sign-off and remediation
- Read-only AD access (any domain user can read most of this) and Entra ID Global Reader

> Run the PowerShell below with the `ActiveDirectory` module (RSAT) and the `Microsoft.Graph` modules. Export each result with `| Export-Csv -NoTypeInformation`, then hash it.

---

## PAM-01 · Inventory privileged accounts

**Objective:** Build a complete population of privileged accounts. Every later test depends on it.

**Evidence — Active Directory privileged groups**
```powershell
$groups = "Domain Admins","Enterprise Admins","Schema Admins","Administrators",
          "Account Operators","Backup Operators","Server Operators","Print Operators",
          "DnsAdmins","Group Policy Creator Owners","Key Admins","Enterprise Key Admins"

foreach ($g in $groups) {
  Get-ADGroupMember -Identity $g -Recursive -ErrorAction SilentlyContinue |
    Where-Object objectClass -eq 'user' |
    Get-ADUser -Properties Enabled,LastLogonDate,PasswordLastSet,PasswordNeverExpires,Description |
    Select-Object @{n='Group';e={$g}},SamAccountName,Name,Enabled,LastLogonDate,PasswordLastSet,PasswordNeverExpires,Description
} | Export-Csv .\ad_privileged_members.csv -NoTypeInformation
```

**Evidence — accounts flagged as protected (AdminCount = 1)**
```powershell
Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount,Enabled,LastLogonDate,PasswordLastSet,PasswordNeverExpires,ServicePrincipalName,mail |
  Select-Object SamAccountName,Enabled,LastLogonDate,PasswordLastSet,PasswordNeverExpires,
                @{n='SPNs';e={$_.ServicePrincipalName -join ';'}},mail |
  Export-Csv .\ad_admincount.csv -NoTypeInformation
```
> `AdminCount` is not cleared when someone leaves a privileged group. Stale entries are themselves a finding, because those accounts keep restrictive ACLs and are often forgotten.

**Evidence — Entra ID (Azure AD) role assignments**
```powershell
Connect-MgGraph -Scopes "RoleManagement.Read.Directory","Directory.Read.All"

# Active (standing) assignments
Get-MgRoleManagementDirectoryRoleAssignmentScheduleInstance -All -ExpandProperty Principal |
  Select-Object @{n='Role';e={(Get-MgRoleManagementDirectoryRoleDefinition -UnifiedRoleDefinitionId $_.RoleDefinitionId).DisplayName}},
                @{n='Principal';e={$_.Principal.AdditionalProperties.userPrincipalName}},AssignmentType,EndDateTime

# Eligible (PIM, just-in-time) assignments
Get-MgRoleManagementDirectoryRoleEligibilityScheduleInstance -All -ExpandProperty Principal
```

**Evidence — Linux / Unix**
```bash
getent group sudo wheel admin 2>/dev/null
awk -F: '$3 == 0 {print $1}' /etc/passwd                 # UID 0 accounts: should be root only
grep -rhE '^[^#].*ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null
```

| Pass | Fail |
|------|------|
| The population is complete and agrees with the PAM vault and the approved access list | Privileged accounts unknown to the control owner |

---

## PAM-02 · Authorisation & least privilege

**Objective:** Each privileged account belongs to a named person (or a documented service), was formally approved, and the privilege fits the role.

**Procedure**
1. Sample from PAM-01, or test 100% if the population is small, as Domain Admins usually is.
2. For each account, get the approval ticket, the approver and the business justification.
3. Challenge the size of Tier 0 groups. Domain Admins should hold a handful of people, not dozens. Everyday tasks should use delegated rights instead.

| Pass | Fail |
|------|------|
| Every account is approved, owned and justified, and Tier 0 groups are small | No approval, generic accounts (`admin2`, `itsupport`), or excessive membership |

---

## PAM-03 · Separate admin accounts

**Objective:** Admins use a separate privileged account, not their daily email and browsing account.

```powershell
# Privileged accounts that also have a mailbox / email address (likely daily-use accounts)
Import-Csv .\ad_admincount.csv | Where-Object { $_.mail -and $_.Enabled -eq 'True' }
```

| Pass | Fail |
|------|------|
| Privileged accounts are dedicated, with no email or web browsing | An admin's normal mailbox account is a Domain Admin |

---

## PAM-04 · Leavers & stale privileged accounts

**Objective:** Privileged access is removed promptly when people leave or change role, and dormant admin accounts are disabled.

```powershell
# Dormant: enabled privileged accounts not used in 90 days
$cutoff = (Get-Date).AddDays(-90)
Import-Csv .\ad_privileged_members.csv |
  Where-Object { $_.Enabled -eq 'True' -and ([string]::IsNullOrEmpty($_.LastLogonDate) -or [datetime]$_.LastLogonDate -lt $cutoff) }
```
> `LastLogonDate` is replicated with up to ~14 days of lag (it comes from `lastLogonTimestamp`), which is fine for a 90-day test.

**Procedure:** Match the HR leaver and mover list for the period against the privileged population. For each leaver who held privilege, check the date access was removed against the leaving date.

| Pass | Fail |
|------|------|
| Access removed by the leaving date (or within policy, e.g. 24 h); no dormant enabled admins | Leavers still enabled, or admin accounts unused for months |

---

## PAM-05 · Strong authentication for privileged access

**Objective:** Privileged access requires MFA, and privileged passwords are strong and rotated.

**Evidence — Entra ID: admins without MFA registered**
```powershell
Connect-MgGraph -Scopes "AuditLog.Read.All","UserAuthenticationMethod.Read.All"
Get-MgReportAuthenticationMethodUserRegistrationDetail -All |
  Where-Object { $_.IsAdmin -and -not $_.IsMfaRegistered } |
  Select-Object UserPrincipalName,IsMfaRegistered,MethodsRegistered
```
> Being *registered* for MFA does not mean MFA is *enforced*. Also review the Conditional Access policies that target admin roles (Entra → Protection → Conditional Access) and check for exclusions.

**Evidence — AD password hygiene**
```powershell
# Privileged accounts with non-expiring passwords
Import-Csv .\ad_admincount.csv | Where-Object PasswordNeverExpires -eq 'True'

# Kerberoastable privileged accounts (SPN set on an admin account)
Get-ADUser -Filter {AdminCount -eq 1 -and ServicePrincipalName -like "*"} -Properties ServicePrincipalName |
  Select-Object SamAccountName,ServicePrincipalName

# krbtgt password age (rotate periodically, and always after a suspected compromise)
Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object PasswordLastSet

# Privileged users in the Protected Users group
Get-ADGroupMember "Protected Users" | Select-Object SamAccountName
```

**Evidence — local admin passwords (LAPS)**
```powershell
# Windows LAPS (new) and legacy LAPS attributes: computers with neither set are not managed
Get-ADComputer -Filter {Enabled -eq $true} -Properties msLAPS-PasswordExpirationTime,ms-Mcs-AdmPwdExpirationTime |
  Where-Object { -not $_.'msLAPS-PasswordExpirationTime' -and -not $_.'ms-Mcs-AdmPwdExpirationTime' } |
  Select-Object Name | Measure-Object
```
> The legacy attribute exists only if the legacy LAPS schema was extended; drop it from `-Properties` if the command errors.

**Evidence — Linux SSH**
```bash
sshd -T | grep -Ei "permitrootlogin|passwordauthentication|pubkeyauthentication"
```

| Pass | Fail |
|------|------|
| MFA enforced for all admin access; no non-expiring passwords on human admins; LAPS on all workstations and servers; root SSH login disabled | Admins without MFA, Kerberoastable admins, the same local admin password everywhere |

---

## PAM-06 · PAM vault coverage, rotation & session recording

**Objective:** Privileged credentials are vaulted, rotated, checked out with approval, and sessions are recorded.

**Procedure**
1. Export the list of accounts onboarded to the vault. Reconcile it with PAM-01 and compute coverage.
2. Check the rotation policy (e.g. after every check-out, or every 30 days). Sample accounts and compare the last rotation date with policy.
3. Pick a sampled check-out. Get the request, approval and session recording, then play back part of the recording.
4. Look for accounts used **outside** the vault, such as direct logons. In the SIEM, compare logons by vaulted accounts against the vault's session log.

```kql
// Sentinel: interactive / RDP logons by privileged accounts not originating from PAM jump servers
SecurityEvent
| where EventID == 4624 and LogonType in (2, 10)
| where TargetUserName in~ (dynamic(["<priv1>","<priv2>"]))   // load from PAM-01
| where IpAddress !in (dynamic(["<pam-jump-ip-1>","<pam-jump-ip-2>"]))
| project TimeGenerated, Computer, TargetUserName, IpAddress, LogonType
```

| Pass | Fail |
|------|------|
| ≥ 95% of privileged accounts vaulted; rotation meets policy; sampled sessions recorded and approved | Large unvaulted population, or vault bypassed by direct logons |

---

## PAM-07 · Break-glass (emergency) accounts

**Objective:** Emergency accounts exist, are protected, are monitored, and are used only in emergencies.

**Procedure:** Identify the break-glass accounts (typically 2 cloud-only Global Admins in Entra, and 1 AD account). Check credential storage (sealed or split custody), any exclusion from Conditional Access and the compensating controls, the alert on any sign-in, and every use during the period against an incident ticket.

```kql
SigninLogs
| where UserPrincipalName in~ ("breakglass1@contoso.onmicrosoft.com","breakglass2@contoso.onmicrosoft.com")
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, AppDisplayName
```

| Pass | Fail |
|------|------|
| Use is alerted, rare, and tied to an incident; credentials are securely stored and tested periodically | No break-glass account (a lockout risk), or one used routinely |

---

## PAM-08 · Monitoring of privileged changes

**Objective:** Additions to privileged groups and roles generate alerts that are reviewed.

| Event | Meaning |
|-------|---------|
| 4728 / 4729 | Member added to / removed from a security-enabled global group |
| 4732 / 4733 | Member added to / removed from a security-enabled local group |
| 4756 / 4757 | Member added to / removed from a security-enabled universal group |
| 4672 | Special privileges assigned to a new logon (admin logon) |
| Entra `Add member to role` | Directory role assignment |

```kql
SecurityEvent
| where EventID in (4728, 4732, 4756)
| where TargetUserName in~ ("Domain Admins","Enterprise Admins","Schema Admins","Administrators")
| project TimeGenerated, Computer, SubjectUserName, MemberName, TargetUserName
```
**Procedure:** Sample changes from this population, match each one to an approved access request, and confirm a SIEM alert exists for unapproved changes.

| Pass | Fail |
|------|------|
| Every privileged change traces to approval; an alert exists | Unexplained group additions, or no alerting |

---

## PAM-09 · Periodic privileged access review

**Objective:** Privileged access is recertified on schedule (commonly quarterly), by someone independent, and removals are carried out.

**Procedure**
1. Get the reviews for the period. Check that the list reviewed was a **system-generated** export from the review date, not a spreadsheet kept by IT.
2. The reviewer must not be reviewing their own access.
3. Trace every "remove" decision to the actual removal date in the system.

| Pass | Fail |
|------|------|
| Complete, independent, timely reviews, with removals done | Rubber-stamped, self-reviewed, or "remove" decisions never executed |

---

**Mapping:** ISO 27001:2022 A.5.15, A.5.18, A.8.2, A.8.5 · NIST CSF 2.0 PR.AA-01, PR.AA-05 · CIS v8 Controls 5, 6 · PCI DSS v4.0 Req. 7, 8
