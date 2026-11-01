# TryHackMe SOC Level 1 — Core SOC Solutions

The main tools a SOC runs on: EDR on the endpoints, a SIEM to centralize and correlate logs, and SOAR to automate the response.

**Rooms:** Introduction to EDR · Introduction to SIEM · Splunk: The Basics · Elastic Stack: The Basics · Introduction to SOAR

> This file covers the two intro rooms. Splunk, Elastic and SOAR are in `Core SOC Solutions Notes.txt`.

**Skills covered:** EDR architecture & telemetry · AV vs. EDR · EDR response actions · log sources · SIEM normalization & correlation · detection rules · alert investigation

---

## Introduction to EDR

**EDR (Endpoint Detection and Response)** monitors endpoints, detects threats on them, and lets you respond from a central console. It exists because laptops spend a lot of time outside the corporate perimeter, so protection has to live on the device itself.

Examples: CrowdStrike Falcon, SentinelOne, Microsoft Defender for Endpoint, Symantec EDR, OpenEDR.

### The three pillars
- **Visibility:** continuous recording of processes, file and registry changes, and user activity. **Process trees** show parent → child relationships, so you can see what spawned what.
- **Detection:** signatures *and* behaviour, which catches fileless malware and anomalies. Detections are often mapped to MITRE ATT&CK.
- **Response:** isolate a host, kill a process, quarantine a file, or open a remote shell, all from the console.

**Limitation:** EDR only sees the host. Network-level threats need NDR/IDS/firewall logs.

### AV vs. EDR
AV is like **passport control**: it checks you against a list at the door. EDR is like **security staff inside the terminal**: they watch behaviour and step in when something looks off.

| Attack stage | Antivirus | EDR |
|---|---|---|
| Phishing doc downloaded | No signature, ignored | Logs the download |
| Macro launches PowerShell | Misses it | Flags Word → PowerShell |
| Obfuscated script injects into `svchost.exe` | Misses it | Flags obfuscation and injection |
| Outbound remote-access connection | No network visibility | Flags the connection |
| **Result** | "System clean" | Alert covering the whole chain |

### Architecture
- **Agent (sensor)** on every endpoint: collects telemetry, streams it to the console in real time, and does some local detection.
- **Console:** central dashboard. Correlates agent data using ML and threat intel, raises alerts, and is where you respond.
- EDR sits alongside the firewall, DLP, email gateway and IAM, and all of them feed into the **SIEM**.

### Telemetry: the endpoint's "flight recorder"
| Telemetry | Helps catch |
|---|---|
| Process start/stop | Suspicious or very short-lived processes |
| Network connections | **C2 beacons**, odd ports, lateral movement |
| Command lines (CMD/PowerShell) | Obfuscated or malicious scripts |
| File/folder changes | Ransomware encryption, data staging, dropped payloads |
| Registry changes | Persistence (Windows settings live in the registry) |

### Detection techniques
Behavioural (e.g. Word spawning PowerShell), anomaly detection (deviation from baseline), **IOC matching** (known-bad hashes, IPs, registry keys), ATT&CK mapping, and ML for multi-stage attacks.

### Response actions
| Action | Use when |
|---|---|
| **Isolate host** | Stop lateral movement. The host stays reachable by the EDR only |
| **Terminate process** | Kill the malicious process but keep the machine running |
| **Quarantine file** | Move the file somewhere safe for review or deletion |
| **Remote shell** | Investigate further or take custom actions |
| **Artifact collection** | Pull memory dumps, event logs, registry hives |

### Lab: triaging EDR alerts
Method: read the detection summary → **Process Info** (name, command line, path) → **Network Activity** (external connections, exfil?) → **Threat Intel** (is this binary actually known internal software?).

Patterns seen in the lab:
- Office doc → `cmd.exe` → `curl` downloading a payload. A payload saved to disk hasn't necessarily been executed.
- **LSASS memory access** means credential dumping. Binaries running from `Temp` or `AppData` are suspicious.
- Check threat intel before escalating. Some "malicious" binaries turn out to be internal tools.

---

## Introduction to SIEM

**SIEM (Security Information and Event Management)** collects logs from endpoints and network devices, stores them centrally, and correlates them.

### The problem with isolated logs
- **Host-centric logs:** activity on one machine (logins, file access, PowerShell). Sources: Windows Event Logs, Sysmon, Osquery.
- **Network-centric logs:** traffic between machines or out to the internet (SSH, web, VPN).

Without a SIEM there's huge volume, no central place to look, a different format per device, and single events that look harmless on their own. Lateral movement only shows up when you **correlate** events across hosts.

### What a SIEM does
1. **Centralized collection** through agents or APIs, so you don't have to log into each box.
2. **Normalization:** parses every format into standard fields (`src_ip`, `user`, `event_id`…).
3. **Correlation:** links events across sources into an attack chain. Example: VPN login → file share access → PowerShell → outbound connection.
4. **Real-time alerting** from built-in and custom rules.
5. **Dashboards and reports:** failed logins, top domains, triggered rules, ingest volume.
6. Plus threat intel integration, long-term retention and advanced search.

### Log sources
- **Windows:** Event Viewer, where every event type has an **Event ID**.
- **Linux:**
```
/var/log/auth.log  or /var/log/secure   # authentication
/var/log/cron                           # scheduled tasks
/var/log/kern                           # kernel
/var/log/httpd  or /var/log/apache      # web server access/errors
```

### Ingestion methods
| Method | How |
|---|---|
| Agent / forwarder | Lightweight program on the host ships logs (e.g. Splunk Universal Forwarder) |
| Syslog | Standard protocol for real-time logs from servers, firewalls, network gear |
| Manual upload | Import offline log files |
| Port forwarding | SIEM listens on a port and devices send to it |

### Correlation rules
Logical conditions that turn events into alerts:
- 5+ failed logins in 10 min → **brute force attempt**
- Success after several failures → **possible successful brute force**
- USB device inserted → **USB access alert**
- Outbound bytes > threshold → **possible exfiltration**

**Worked example rules:**
```
If Log Source = WinEventLog AND EventID = 104
  → Alert: "Event Log Cleared"            # attacker covering tracks

If Log Source = WinEventLog AND EventID = 4688
   AND NewProcessName contains "whoami"
  → Alert: "Recon Command Executed"       # 4688 = process creation
```

### Investigating an alert
1. Open the alert and the events behind it, and see which rule condition matched.
2. **False positive** → tune the rule so the benign activity stops triggering it.
3. **True positive** → dig deeper, contact the asset owner, isolate the host, block the malicious IPs.

The lab is a simulated SIEM dashboard: trigger the suspicious activity, pivot from the alert to the process, user and host, read which rule keyword matched, and record a TP/FP verdict.
