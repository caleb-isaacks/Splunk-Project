# Splunk-Project
# SSH Brute Force → Root Account Compromise  
Splunk SIEM Investigation 
Caleb Isaacks

---

## Overview  
This project simulates a real-world brute-force attack against a Linux host, followed by a successful compromise of the root account.  
Using Splunk Enterprise, I ingested authentication logs, identified attack patterns, built a timeline of attacker activity, and documented the incident using SOC investigative workflows.

This hands-on lab demonstrates core skills required for SOC Analyst, Threat Detection, and Incident Response roles.

---

## Objectives  
- Set up Splunk In Linux VM
- Ingest Linux authentication logs into Splunk  
- Detect brute-force attempts  
- Identify a successful account compromise  
- Build a full attack timeline  
- Map findings to MITRE ATT&CK  
- Produce a SOC-style triage report  

---

## Data Source  
File: Linux `auth.log` sample dataset (simulated)  
Index: `auth_logs`  
Source Type: `linux_secure`  
Environment: Splunk Enterprise (local VM install)

---

## Key Findings  
- Attacker IP: 185.222.81.23 
- Failed Login Attempts: 6  
- Successful Login: root 
- Attack Vector: SSH brute force leading to credential compromise  
- Severity: High root-level access gained

---

## Search Queries Used  

## 1. Failed Login Attempts  
```spl
index=auth_logs "Failed password"
```
## 2. Successful Login Attempts
```spl
index=auth_logs "Accepted password"
```
## 3. Event Timeline
```spl
index=auth_logs ("Failed password" OR "Accepted password")
| eval status=case(
    searchmatch("Failed password"), "Failed Login",
    searchmatch("Accepted password"), "Successful Login"
  )
| eval attack_stage=case(
    status="Failed Login", "Brute Force Attempt",
    status="Successful Login", "Account Compromise"
  )
| table _time, src, user, status, attack_stage
| sort _time
```
## Summary of Timeline
| Time        | Source IP     | User       | Status           | Attack Stage        |
| ----------- | ------------- | ---------- | ---------------- | ------------------- |
| 14:02–14:04 | 185.222.81.23 | admin/root | Failed Login     | Brute Force Attempt |
| 14:05       | 185.222.81.23 | root       | Successful Login | Account Compromise  |

## MITRE ATT&CK Framework Mapping
| Technique ID | Name                | Description                          |
| ------------ | ------------------- | ------------------------------------ |
| T1110        | Brute Force         | Multiple failed login attempts       |
| T1078        | Valid Accounts      | Attacker used legitimate credentials |
| T1021.004    | Remote Services SSH | Access gained through SSH            |

## SOC Report
Severity: High
- Impact: Unauthorized root-level access to the system
- Category: Authentication Brute Force Credential Compromise
- Likelihood: Confirmed malicious activity

Indicators of Compromise (IoCs)
- IP Address: 185.222.81.23
- SSH activity on port 22
- Failed login attempts prior to Successful login 
- Targeted privileged account: root

Recommended Actions
- Isolate the affected host
- Reset all privileged credentials
- Block attacker IP at the network perimeter
- Review /var/log/auth.log, /var/log/syslog, and user command history
- Check for persistence (cron jobs, new users, SSH keys)


<img width="1710" height="987" alt="image" src="https://github.com/user-attachments/assets/ff04c4a0-8671-4d25-80e8-ea90a4ea9c9d" />
