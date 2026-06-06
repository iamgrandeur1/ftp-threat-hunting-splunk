# FTP File Transfer Monitoring & Threat Hunting Using Splunk

---

## Overview

This project focused on analyzing FTP traffic using Splunk and Zeek FTP logs to investigate user activity, file transfer behavior, server responses, and potential indicators of suspicious activity.

FTP remains an important protocol to monitor because it is frequently associated with file transfers, data staging, and legacy infrastructure.

---

## Objective

To analyze FTP communications, identify common FTP operations, investigate user activity, and monitor file transfer behavior through threat hunting workflows.

---

## Lab Setup

- Log Source: Zeek (`ftp.log`)
- SIEM: Splunk
- Environment: Virtual Lab (Kali Linux + VirtualBox)

---

## Dataset

The FTP logs contained:

- Source IP addresses
- Destination IP addresses
- FTP usernames
- FTP commands
- File transfer operations
- FTP response codes
- Server responses

---

## Detection Methodology

### 1. FTP Command Analysis

```spl
index=main sourcetype=zeek_ftp
| rex field=_raw "^\S+\s+\S+\s+\S+\s+\d+\s+\S+\s+\d+\s+\S+\s+\S+\s+(?<ftp_command>\S+)"
| stats count by ftp_command
| sort - count
```

### 2. FTP User Analysis

```spl
index=main sourcetype=zeek_ftp
| stats count by ftp_user
| sort - count
```

### 3. FTP Response Code Analysis

```spl
index=main sourcetype=zeek_ftp
| stats count by response_code
| sort - count
```

---

## Analysis & Findings

### Most Common FTP Response Codes

| Response Code | Count |
|---------------|------:|
| 227 | 2830 |
| 550 | 2711 |
| 226 | 70 |
| 200 | 57 |
| 530 | 28 |

### Top FTP Users

| User | Activity Count |
|--------|-------------:|
| password@example.com | 5404 |
| password | 199 |
| justinwray@justinwray.com | 44 |
| IEUser@ | 31 |
| Cuno | 25 |

### Observed FTP Operations

The dataset contained several FTP operations including:

- PASV (Passive Mode)
- STOR (File Upload)
- DELE (File Deletion)

### Sample Activity

Examples observed during investigation:

- File upload attempts using `STOR`
- File deletion attempts using `DELE`
- Passive FTP session establishment using `PASV`
- Multiple permission-denied responses (`550`)

---

## SOC Insight

FTP traffic can reveal valuable information about user behavior, file movement, and potential data transfer activity.

During this investigation:

- FTP uploads were observed
- File deletion attempts were identified
- User activity patterns were analyzed
- Numerous permission-denied responses were detected

Large numbers of failed file operations may indicate access control issues, misconfigurations, or suspicious activity requiring further investigation.

---

## Key Takeaway

File transfer protocols remain an important monitoring area within SOC operations.

Analyzing FTP activity provides visibility into user behavior, file movement, server interactions, and potential indicators of compromise.

---

## Next Steps

- Correlate FTP activity with authentication logs
- Monitor large file transfer activity
- Develop FTP anomaly detection rules
- Create FTP monitoring dashboards
- Investigate unusual file access patterns

---

## Sample Output

Add screenshots:

```markdown
![FTP User Analysis](ftp-users.png)

![FTP Response Codes](ftp-response-codes.png)

![FTP Activity](ftp-activity.png)
```

---

## Skills Demonstrated

- Splunk SPL
- FTP Analysis
- Threat Hunting
- Detection Engineering
- Network Traffic Analysis
- File Transfer Monitoring
- Log Analysis
- SIEM Operations
- SOC Analysis
- Zeek Log Analysis
