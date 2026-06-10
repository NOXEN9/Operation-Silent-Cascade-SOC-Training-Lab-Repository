# Elastic Stack Detections: Operation Silent Cascade

**Target Platform:** Elastic Stack 8.x
**Detection Type:** KQL (Kibana Query Language), Threshold Alerting Rules, and Machine Learning Configurations

---

## Contents

1. [Initial Access — Phishing Detection](#1-initial-access--phishing-detection)
2. [Execution — Office Spawning PowerShell](#2-execution--office-spawning-powershell)
3. [Defense Evasion — Rundll32 LOLBin](#3-defense-evasion--rundll32-lolbin)
4. [Persistence — Scheduled Task Creation](#4-persistence--scheduled-task-creation)
5. [Persistence — Registry Run Key](#5-persistence--registry-run-key)
6. [Credential Access — LSASS Dumping](#6-credential-access--lsass-dumping)
7. [Credential Access — DCSync Detection](#7-credential-access--dcsync-detection)
8. [Lateral Movement — SMB Admin Share](#8-lateral-movement--smb-admin-share)
9. [Exfiltration — DNS Tunneling](#9-exfiltration--dns-tunneling)
10. [Defense Evasion — File Deletion](#10-defense-evasion--file-deletion)
11. [Threshold Alerting Rules](#11-threshold-alerting-rules)
12. [Elastic ML Job Configurations](#12-elastic-ml-job-configurations)

---

## 1. Initial Access — Phishing Detection

### Detect Suspicious Email Attachment Extensions

```kql
event.category : "email"
and event.type : "info"
and email.attachments.file.extension : ("xlsm", "xlsb", "docm", "pptm", "vba", "vbe", "js", "hta", "ps1")
and not email.attachments.file.name : "*signed*"
```

### Detect Emails from New or Unusual Sender Domains

```kql
event.category : "email"
and event.type : "info"
and not email.from.address : "*@corp.local"
and email.subject : ("*financial*", "*review*", "*action required*", "*urgent*", "*payment*", "*invoice*")
```

---

## 2. Execution — Office Spawning PowerShell

### Detect Office Application Spawning PowerShell

This query detects the critical execution chain where Excel spawns a PowerShell process — the primary initial access payload delivery mechanism.

```kql
process.parent.name : ("EXCEL.EXE", "WINWORD.EXE", "POWERPNT.EXE", "OUTLOOK.EXE")
and process.name : "powershell.exe"
and process.command_line : ("*-ExecutionPolicy Bypass*", "*-WindowStyle Hidden*", "*DownloadString*", "*IEX*", "*Net.WebClient*")
```

### Enhanced Detection with Network Correlation

```kql
sequence by host.name with maxspan=30s
  [process where event.type == "start"
   and process.parent.name : ("EXCEL.EXE", "WINWORD.EXE")
   and process.name : "powershell.exe"]
  [network where event.type == "connection"
   and destination.ip : ("203.0.113.100", "203.0.113.50")
   and destination.port == 8443]
```

---

## 3. Defense Evasion — Rundll32 LOLBin

### Detect Suspicious Rundll32 Execution

Detects rundll32.exe executed from user-writable locations or with suspicious command-line patterns.

```kql
process.name : "rundll32.exe"
and event.type : "start"
and (
  process.command_line : ("*\\Users\\*", "*\\AppData\\*", "*\\Temp\\*", "*\\Downloads\\*")
  or process.working_directory : ("*\\Users\\*", "*\\Temp\\*")
)
and not process.executable : ("C:\\Windows\\System32\\*", "C:\\Windows\\SysWOW64\\*")
```

### Detect Office → PowerShell → Rundll32 Chain

```kql
sequence by host.name with maxspan=60s
  [process where event.type == "start"
   and process.parent.name : ("EXCEL.EXE", "WINWORD.EXE")
   and process.name : "powershell.exe"]
  [process where event.type == "start"
   and process.name : "rundll32.exe"
   and process.command_line : "*update.dll*"]
```

---

## 4. Persistence — Scheduled Task Creation

### Detect Scheduled Task Creation via Event 4698

```kql
event.code : "4698"
and winlog.event_data.TaskName : "*"
and not winlog.event_data.TaskContent : "*Microsoft*"
```

### Detect Scheduled Tasks with PowerShell Triggers

```kql
event.code : "4698"
and winlog.event_data.TaskContent : "*powershell*"
and not winlog.event_data.TaskContent : ("*WindowsDefender*", "*WindowsUpdate*")
```

### Detect High-Frequency Scheduled Tasks

```kql
event.code : "4698"
and winlog.event_data.TaskContent : "*<Repetition><Interval*"
```

### Detect DCSyncJob Specifically

```kql
event.code : "4698"
and winlog.event_data.TaskName : "DCSyncJob"
```

---

## 5. Persistence — Registry Run Key

### Detect Registry Run Key Creation from Suspicious Parent Processes

```kql
event.category : "registry"
and event.type : ("creation", "change")
and registry.path : "*\\Software\\Microsoft\\Windows\\CurrentVersion\\Run*"
and process.name : "rundll32.exe"
```

### Broad Registry Run Key Monitoring

```kql
event.category : "registry"
and event.type : ("creation", "change")
and registry.path : "*\\CurrentVersion\\Run*"
and not process.executable : ("C:\\Windows\\System32\\msiexec.exe", "C:\\Windows\\System32\\Taskmgr.exe", "C:\\Program Files\\*")
```

---

## 6. Credential Access — LSASS Dumping

### Detect Procdump Against LSASS

```kql
process.name : "procdump64.exe" or process.name : "procdump.exe"
and process.command_line : "*lsass*"
and process.command_line : ("*-ma*", "*-mm*")
```

### Detect Any Process Accessing LSASS with Suspicious Callback

```kql
event.category : "process"
and event.type : "start"
and process.name : ("procdump64.exe", "procdump.exe", "mimikatz.exe", "powersploit*", "cobaltstrike*")
and process.command_line : "*lsass*"
```

### Detect LSASS Dump File Creation

```kql
file.name : "lsass.dmp"
or file.extension : "dmp"
and file.path : "*\\Temp\\*"
```

---

## 7. Credential Access — DCSync Detection

### Detect DCSync via Event 4662

```kql
event.code : "4662"
and winlog.event_data.ObjectType : "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
and winlog.event_data.AccessMask : "*DS-Replication-Get-Changes*"
```

### Detect DCSync via Event 4662 (Both GUIDs)

```kql
event.code : "4662"
and winlog.event_data.ObjectType : ("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")
and winlog.event_data.AccessMask : ("*DS-Replication-Get-Changes*", "*DS-Replication-Get-Changes-All*")
and not winlog.event_data.SubjectUserName : ("*DC*$", "*SERVER*$", "*MSOL_*")
```

### Detect Mimikatz Execution via Command Line

```kql
process.name : "mimikatz.exe"
or process.command_line : ("*lsadump*", "*dcsync*", "*::*", "*sekurlsa*", "*kerberos*", "*golden*")
```

---

## 8. Lateral Movement — SMB Admin Share

### Detect SMB Administrative Share Access

```kql
event.code : "4624"
and winlog.event_data.LogonType : "3"
and winlog.event_data.TargetUserName : ("Administrator", "a.mitchell", "s.johnson")
and winlog.event_data.WorkstationName : "WORKSTATION-01"
```

### Detect Network Connections to Domain Controller on SMB

```kql
network.transport : "tcp"
and destination.port : 445
and destination.ip : ("10.10.1.10", "10.10.1.20")
and source.ip : ("10.10.2.100", "10.10.1.10")
and event.action : "network-connection"
```

### Detect Anomalous Admin Share Access

```kql
event.code : "5140"
and winlog.event_data.ShareName : ("*ADMIN$*", "*C$*", "*IPC$*")
and not winlog.event_data.SubjectUserName : ("*$", "SYSTEM")
```

---

## 9. Exfiltration — DNS Tunneling

### Detect High-Volume DNS Queries to Suspicious Domains

```kql
dns.question.name : "*trustedservices.online"
or dns.question.name : "*cloud-cdn.net"
or dns.question.name : "*corp-finance-review.com"
```

### Detect DNS TXT Record Queries

```kql
dns.question.type : "TXT"
and dns.question.name : "*trustedservices.online"
```

### Detect High Volume of DNS Queries from Single Source

```kql
event.category : "network"
and network.protocol : "dns"
and destination.ip : "203.0.113.50"
and source.ip : ("10.10.1.10", "10.10.2.100")
```

### Detect Base64-Encoded Subdomains (High Entropy)

```kql
dns.question.name : "*test.data.trustedservices.online"
and dns.question.type : "TXT"
```

### Detect DNS Queries with Long Subdomain Labels

```kql
dns.question.name : "*.trustedservices.online"
and length(dns.question.name) > 50
```

---

## 10. Defense Evasion — File Deletion

### Detect Mass File Deletion via cmd.exe

```kql
process.name : "cmd.exe"
and process.command_line : "*del /q*"
and process.command_line : ("*output.zip*", "*.dmp*", "*mimikatz*")
```

### Detect Suspicious File Delete Events

```kql
event.category : "file"
and event.type : "deletion"
and file.name : ("output.zip", "lsass.dmp", "mimikatz.exe", "update.dll", "stage1.ps1", "dc_update.ps1")
```

---

## 11. Threshold Alerting Rules

### Rule 1: High-Volume DNS Queries per Host

**Description:** Alerts when a single host exceeds 100 DNS queries to a previously unseen domain within 5 minutes.

```json
{
  "rule_id": "THR-DNS-001",
  "type": "threshold",
  "name": "High Volume DNS Queries to Suspicious Domain",
  "threshold": {
    "field": "dns.question.name",
    "value": 100,
    "cardinality": [
      {
        "field": "host.name"
      }
    ]
  },
  "timeframe": {
    "minutes": 5
  },
  "query": "dns.question.type : \"TXT\" and dns.question.name : \"*trustedservices.online\"",
  "severity": "high",
  "risk_score": 75,
  "tags": ["T1048.003", "DNS Exfiltration", "APT-SILENT-47"]
}
```

### Rule 2: Unique Subdomain Spike per Minute

**Description:** Alerts when more than 20 unique subdomains are queried against a single domain within 1 minute.

```json
{
  "rule_id": "THR-DNS-002",
  "type": "threshold",
  "name": "Unique Subdomain Spike - Potential DNS Tunneling",
  "threshold": {
    "field": "dns.question.name",
    "value": 20
  },
  "timeframe": {
    "minutes": 1
  },
  "query": "dns.question.type : (\"TXT\", \"A\", \"AAAA\")",
  "severity": "high",
  "risk_score": 80,
  "tags": ["T1048.003", "DNS Tunneling"]
}
```

### Rule 3: Office Application Spawning PowerShell

**Description:** Alerts on any Office application spawning a PowerShell process with suspicious command-line arguments.

```json
{
  "rule_id": "THR-EXEC-001",
  "type": "threshold",
  "name": "Office Application Spawning PowerShell - Possible Macros",
  "threshold": {
    "field": "host.name",
    "value": 1
  },
  "timeframe": {
    "minutes": 1
  },
  "query": "process.parent.name : (\"EXCEL.EXE\", \"WINWORD.EXE\", \"POWERPNT.EXE\") and process.name : \"powershell.exe\"",
  "severity": "critical",
  "risk_score": 95,
  "tags": ["T1059.001", "T1204.002", "Macro Execution"]
}
```

### Rule 4: DCSync Replication Event

**Description:** Alerts on Event 4662 with DS-Replication-Get-Changes access from a non-DC computer account.

```json
{
  "rule_id": "THR-CRED-001",
  "type": "threshold",
  "name": "Potential DCSync Attack Detected",
  "threshold": {
    "field": "host.name",
    "value": 1
  },
  "timeframe": {
    "minutes": 5
  },
  "query": "event.code : \"4662\" and winlog.event_data.AccessMask : \"*DS-Replication-Get-Changes*\" and not winlog.event_data.SubjectUserName : \"*$\"",
  "severity": "critical",
  "risk_score": 99,
  "tags": ["T1003.006", "DCSync", "Credential Access"]
}
```

### Rule 5: Anomalous Scheduled Task Creation

**Description:** Alerts on scheduled task creation from non-standard parent processes.

```json
{
  "rule_id": "THR-PERSIST-001",
  "type": "threshold",
  "name": "Suspicious Scheduled Task Creation",
  "threshold": {
    "field": "host.name",
    "value": 1
  },
  "timeframe": {
    "minutes": 5
  },
  "query": "event.code : \"4698\" and winlog.event_data.TaskContent : \"*powershell*\"",
  "severity": "high",
  "risk_score": 85,
  "tags": ["T1053.005", "Persistence", "Scheduled Task"]
}
```

---

## 12. Elastic ML Job Configurations

### ML Job 1: Rare DNS Domain Detection

**Description:** Detects DNS queries to domains rarely or never seen in the environment. Useful for identifying C2 and DNS tunneling infrastructure.

```json
{
  "job_id": "ml-dns-rare-domain",
  "description": "Detects rare DNS domains queried per host - indicators of C2 or DNS tunneling",
  "analysis_config": {
    "bucket_span": "15m",
    "detectors": [
      {
        "detector_description": "Rare DNS domain per source IP",
        "function": "rare",
        "by_field_name": "dns.question.name",
        "partition_field_name": "source.ip"
      }
    ],
    "influencers": ["source.ip", "host.name", "dns.question.name"]
  },
  "data_description": {
    "time_field": "@timestamp",
    "time_format": "epoch_ms"
  },
  "model_plot_config": {
    "enabled": true
  },
  "custom_settings": {
    "security": {
      "mitre_ids": ["T1071.004", "T1048.003"],
      "threat_actor": "APT-SILENT-47"
    }
  }
}
```

### ML Job 2: DNS Query Volume Spike Detection

**Description:** Detects sudden spikes in DNS query volume from a single host — indicative of bulk data exfiltration via DNS tunneling.

```json
{
  "job_id": "ml-dns-volume-spike",
  "description": "Detects abnormal spikes in DNS query volume per host - potential DNS exfiltration",
  "analysis_config": {
    "bucket_span": "5m",
    "detectors": [
      {
        "detector_description": "High count of DNS queries per source IP",
        "function": "high_count",
        "by_field_name": "dns.question.type",
        "partition_field_name": "source.ip",
        "over_field_name": "host.name"
      }
    ],
    "influencers": ["source.ip", "host.name", "dns.question.name"]
  },
  "data_description": {
    "time_field": "@timestamp",
    "time_format": "epoch_ms"
  },
  "model_plot_config": {
    "enabled": true
  },
  "custom_settings": {
    "security": {
      "mitre_ids": ["T1048.003"],
      "expected_query_rate_per_host": 10,
      "alerting_threshold_multiplier": 5
    }
  }
}
```

### ML Job 3: First-Seen Domain Detection

**Description:** Detects DNS queries to domains that have never been observed in the environment before — useful for identifying newly registered malicious domains.

```json
{
  "job_id": "ml-dns-new-domain",
  "description": "Detects first-seen domains per host - potential C2 or phishing infrastructure",
  "analysis_config": {
    "bucket_span": "1h",
    "detectors": [
      {
        "detector_description": "Rare DNS domain per host (new domain detection)",
        "function": "rare",
        "by_field_name": "dns.question.registered_domain",
        "partition_field_name": "host.name"
      }
    ],
    "influencers": ["host.name", "source.ip", "dns.question.registered_domain"]
  },
  "data_description": {
    "time_field": "@timestamp",
    "time_format": "epoch_ms"
  },
  "model_plot_config": {
    "enabled": true
  },
  "rules": [
    {
      "actions": ["skip_result"],
      "conditions": [
        {
          "applies_to": "actual",
          "operator": "lt",
          "value": 1
        }
      ]
    }
  ],
  "custom_settings": {
    "security": {
      "mitre_ids": ["T1071.004", "T1566.001"],
      "domain_age_threshold_hours": 48
    }
  }
}
```

### ML Job 4: Abnormal Process Chain Detection

**Description:** Detects anomalous parent-child process relationships, specifically Office applications spawning scripting runtimes.

```json
{
  "job_id": "ml-process-chain-anomaly",
  "description": "Detects anomalous process chains - Office spawning PowerShell/CMD/WScript",
  "analysis_config": {
    "bucket_span": "15m",
    "detectors": [
      {
        "detector_description": "Rare process chain - unusual parent-child relationship",
        "function": "rare",
        "by_field_name": "process.name",
        "partition_field_name": "process.parent.name",
        "over_field_name": "host.name"
      }
    ],
    "influencers": ["host.name", "process.name", "process.parent.name"],
    "categorization_field_name": "process.command_line"
  },
  "data_description": {
    "time_field": "@timestamp",
    "time_format": "epoch_ms"
  },
  "model_plot_config": {
    "enabled": false
  },
  "custom_settings": {
    "security": {
      "mitre_ids": ["T1059.001", "T1204.002", "T1218.011"],
      "known_benign_parent_child": [
        "EXCEL.EXE -> EXCEL.EXE",
        "WINWORD.EXE -> WINWORD.EXE",
        "OUTLOOK.EXE -> EXCEL.EXE"
      ]
    }
  }
}
```

### ML Job 5: DNS TXT Record Entropy Detection

**Description:** Detects DNS TXT queries containing high-entropy subdomain labels, characteristic of Base64-encoded data tunneling.

```json
{
  "job_id": "ml-dns-txt-entropy",
  "description": "Detects DNS TXT queries with high-entropy subdomain labels - encoded data exfiltration",
  "analysis_config": {
    "bucket_span": "5m",
    "detectors": [
      {
        "detector_description": "High information entropy in DNS query subdomain labels",
        "function": "high_info_content",
        "by_field_name": "dns.question.name",
        "partition_field_name": "source.ip",
        "over_field_name": "host.name"
      }
    ],
    "influencers": ["host.name", "source.ip", "dns.question.name"],
    "categorization_field_name": "dns.question.name"
  },
  "data_description": {
    "time_field": "@timestamp",
    "time_format": "epoch_ms"
  },
  "model_plot_config": {
    "enabled": true
  },
  "custom_settings": {
    "security": {
      "mitre_ids": ["T1048.003"],
      "encoding_patterns": ["Base64", "Base32", "hex"],
      "entropy_threshold": 4.5
    }
  },
  "analysis_limits": {
    "model_memory_limit": "128mb"
  }
}
```

---

## Deployment Notes

### Required Elastic Integrations

| Integration | Purpose |
|---|---|
| Windows Event Logs | Process creation (4688), scheduled tasks (4698), logon events (4624), directory access (4662) |
| Windows Defender / Sysmon | Process ancestry, network connections, registry modifications |
| DNS (Windows DNS Server or Zeek) | DNS query logs for tunneling detection |
| Network Traffic (Zeek / Packetbeat) | SMB connections, C2 traffic, outbound TLS |
| Elastic Endpoint Security | EDR-based behavioral detection and response |

### Recommended Alert Actions

| Rule ID | Response Action |
|---|---|
| THR-DNS-001 | Isolate host via EDR, block domain at DNS firewall |
| THR-EXEC-001 | Terminate process chain, isolate workstation, block C2 IP |
| THR-CRED-001 | Disable krbtgt reset timer, isolate domain controller, initiate IR |
| THR-PERSIST-001 | Remove scheduled task, audit for additional persistence |

### Playbook Integration

Each threshold rule is designed for automatic playbook triggering. On alert confirmation:
1. **Triage:** Verify alert against threat intelligence feeds
2. **Contain:** Apply host isolation via EDR (Elastic Endpoint or Defender)
3. **Eradicate:** Remove persistence mechanisms, rotate affected credentials
4. **Recover:** Apply GPO hardening, reset krbtgt if DCSync confirmed
5. **Post-Mortem:** Update detection rules and ML models based on forensic findings
