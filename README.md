# Operation: Silent Cascade — SOC Training Lab Repository

## Repository Overview

This repository contains the complete, enterprise-grade documentation for **Operation: Silent Cascade**, a Level 1 SOC Analyst training simulation based on a real-world Advanced Persistent Threat (APT) intrusion. The scenario details a Business Email Compromise (BEC) leading to full domain compromise, credential theft via DCSync, and data exfiltration through DNS tunneling.

The attack was executed by **APT-SILENT-47**, a financially motivated threat actor who leveraged a spearphishing email with a malicious Excel macro to gain initial access to the `corp.local` Active Directory environment. Over a four-day period (September 16–19, 2024), the attacker escalated privileges, moved laterally across three servers and approximately 150 workstations, established multiple persistence mechanisms, and exfiltrated sensitive financial data before indicators of compromise were identified.

## Scenario Background

**Environment:** `corp.local` — Active Directory domain (3 servers, ~150 workstations)

**Incident ID:** INC-2024-07182

**Classification:** APT / Business Email Compromise → Data Exfiltration

**Severity:** CRITICAL

**Threat Actor:** APT-SILENT-47

On September 16, 2024, a finance department user on `WORKSTATION-01` received a spearphishing email purporting to contain a Q3 financial review. The attached macro-enabled workbook (`Q3_Financial_Review.xlsm`) executed a PowerShell payload that established command-and-control (C2) communication with attacker-controlled infrastructure. The attacker subsequently dumped LSASS credentials, performed a DCSync attack against the domain controller (`DC-01`), moved laterally via SMB to the file server (`FILESERVER-01`), collected sensitive documents, and exfiltrated data over DNS tunneling to `data.trustedservices.online`.

## Attacker Infrastructure

| Indicator | Type | IP Address |
|---|---|---|
| corp-finance-review.com | Phishing Domain | 198.51.100.77 |
| update-service.cloud-cdn.net | C2 Domain | 203.0.113.50 |
| C2 Listener (Direct) | C2 IP | 203.0.113.100:8443 |
| data.trustedservices.online | DNS Tunnel Domain | 203.0.113.50 |
| staging.trustedservices.online | Staging Domain | 203.0.113.51 |

## Key Artifacts

| Artifact | Type | Details |
|---|---|---|
| Q3_Financial_Review.xlsm | Malicious Attachment | Macro-enabled Excel workbook |
| stage1.ps1 | PowerShell Payload | Initial staging script |
| update.dll | Malicious DLL | Loaded via rundll32.exe |
| lsass.dmp | Credential Dump | procdump64.exe output |
| Client_Portfolio_2024.xlsx | Exfiltrated Data | Sensitive financial document |
| M&A_Due_Diligence.docx | Exfiltrated Data | Confidential M&A document |
| output.zip | Archives Exfiltrated Data | Exfiltrated via DNS tunnel |
| dc_update.ps1 | Persistence Script | Scheduled task on DC-01 |

## Table of Contents

| Document | Description |
|---|---|
| [Executive Incident Report](report.md) | Formal incident report including Executive Summary, Root Cause Analysis, timeline narrative, containment steps, and GPO-based remediation recommendations | 
| [Attack Timeline](timeline.md) | Chronological event log with Mermaid.js sequence diagram visualizing the full kill chain |
| [MITRE ATT&CK Mapping](mitre_mapping.md) | Comprehensive mapping of adversary Tactics, Techniques, and Procedures (TTPs) with contextual procedure descriptions |
| [Elastic Stack Detections](kql_detections.md) | Production-ready KQL queries, threshold alerting rules, and Elastic ML job configurations for detecting each phase of the attack |
| [Evidence Gallery](Evidence) | Forensic artifact collection with mapped screenshots of each attack phase including PowerShell execution, persistence mechanisms, credential dumping, DCSync activity, DNS tunneling, and Elastic Security alerts |
