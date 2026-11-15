# TryHackMe SOC Level 1 — SIEM Triage for SOC

The module where everything comes together in the SIEM. Earlier modules taught the log sources (Windows, Linux, web, network) and the attacks. Here you triage real alerts end to end in **Splunk** and **Elastic**, then run two investigations on your own.

**Rooms:** Log Analysis with SIEM · Alert Triage With Splunk · Alert Triage With Elastic · ItsyBitsy (challenge) · Benign (challenge)

**Skills covered:** SIEM centralization & correlation · time zones & normalization · Windows/Linux/web log sources in a SIEM · SPL triage queries · KQL in Kibana Discover · brute force, persistence & web shell alerts · pivoting from one indicator to the full story

---

## Log Analysis with SIEM

### Why analysts need a SIEM
- **Centralization:** one search across every host instead of logging into each one
- **Correlation:** link events from different sources into one chain (VPN login → file access → PowerShell → outbound connection)
- **History:** search back weeks or months, long after logs roll off the endpoint

### Log source categories
| Category | Examples |
|---|---|
| **Host-based** | Windows Security/System logs, Sysmon, Linux `auth.log`, `syslog`, auditd |
| **Network-based** | Firewalls, routers, IDS/IPS, proxies |
| **Web** | Apache/Nginx access and error logs, WAF |
| Out of scope here | Cloud platforms, identity providers, SaaS apps |

### Two things that trip people up
- **Time zones:** a firewall logging in UTC and a server in local time put the same event hours apart. Check each source's time zone before building a timeline
- **Normalization:** the same concept has different field names per source (`src_ip`, `SourceIp`, `client`). The SIEM maps them to common fields so one query covers them all

### What each source is good for
| Source | Look for | Key fields / IDs |
|---|---|---|
| **Windows** | Logons, process creation, new accounts, new services | 4624/4625, 4688, 4720/4732, 7045 · Sysmon 1, 3, 11, 13 |
| **Linux** | SSH brute force, sudo, new users, cron | `auth.log` (`Failed password`, `Accepted`, `useradd`), `syslog` (`CRON`) |
| **Web** | Brute force (Hydra), web shells, DDoS | Client IP, URI, status, size, user agent |

---

## Alert Triage With Splunk

Three alerts, each from a different source, all following the same triage method from **SOC L1 Alert Triage**: assign → understand the alert → investigate → verdict + 5 Ws report.

> Set the time picker to **All Time** in the lab, or Splunk only searches the last 24 hours and returns nothing.

### 1. Initial access: Linux SSH brute force
```spl
index=linux sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip, user | sort -count

index=linux sourcetype=linux_secure "Accepted" src_ip=<attacker IP>
```
**Verdict logic:** lots of failures + **a success from the same IP** = true positive, compromised account → escalate. Failures only = attempted brute force: block the IP and close.
What happened next: `sudo` use, new users, and downloads for that user after the login time.

### 2. Persistence: Windows
```spl
index=windows EventCode=4698 OR EventCode=7045 OR (EventCode=13 TargetObject="*\\CurrentVersion\\Run*")
| table _time, host, User, TaskName, ServiceName, ImagePath, TargetObject, Details
```
Then trace **what created it**: find the process creation (Sysmon 1 / 4688) that ran `schtasks`, `sc` or `reg`, and walk up the `ParentImage` chain to the initial payload.
**Red flags:** binary in `C:\Users\Public`, `AppData`, `Temp` · benign-sounding name (`WindowsUpdate`) · created by `powershell.exe` or an Office app.

### 3. Web shell
```spl
index=web sourcetype=access_combined method=POST
| stats count by clientip, uri | sort -count

index=web uri="*/uploads/*.php*" | table _time, clientip, method, uri, status, useragent
```
**Pattern:** an upload request → a new `.php` in an upload directory → repeated `POST`/`GET ?cmd=` requests to it from one IP. Confirm with host logs if you have them (web server process spawning a shell).

**Useful SPL building blocks:**
```spl
| stats count by field            # group and count
| sort -count                     # descending
| table _time, f1, f2             # pick columns
| rex "regex (?<name>...)"         # extract a field from raw text
| timechart span=5m count         # activity over time
| dedup field                     # unique values
```

---

## Alert Triage With Elastic

The same skill in the other major stack: investigate alerts in **Kibana** using **Discover** and **KQL**.

**Discover workflow:** pick the index pattern / data view → **set the time range** → search with KQL → add fields as columns → click a field in the sidebar to see its **top values** (an instant "who's the top talker?").

**KQL syntax:**
```
event.code : 4625
event.code : 4625 and user.name : "admin"
source.ip : 10.10.* and not destination.port : 443
process.command_line : *certutil*            # wildcards
url.path : "/login.php" and http.response.status_code : 200
```
- `:` = equals (case-insensitive for keyword fields), `and` / `or` / `not`, `*` wildcards
- Field names follow the **Elastic Common Schema (ECS)**: `source.ip`, `user.name`, `process.parent.name`, `event.code`, so the same query works across sources

**Splunk ↔ Elastic:**
| Task | Splunk (SPL) | Elastic (KQL / Kibana) |
|---|---|---|
| Filter | `index=x EventCode=4625` | `event.code : 4625` |
| Top values | `\| stats count by src_ip` | Field sidebar → top values, or a visualization |
| Over time | `\| timechart count` | Discover histogram / Lens chart |
| Extract fields | `\| rex` | Done at ingest (ingest pipelines) |

The triage logic doesn't change between tools. Only the query language does.

---

## ItsyBitsy (challenge, ELK)

**Scenario:** an IDS raised a possible **C2 communication** alert for one user's machine. You have about a week of **HTTP connection logs** in Kibana and need to find out what happened.

**What it practises:**
- Narrowing by **time range** and the suspicious host's **source IP**
- Using field top-values on `user_agent` / destination host to spot the outlier
- Recognizing a **LOLBin user agent** (e.g. `bitsadmin` / BITS shows up as `Microsoft BITS/7.x`), because a built-in download tool showing up in web logs is a strong signal
- Following the connection to a **file-sharing / paste site** and working out what was downloaded

**Lesson:** user agents are an underrated pivot. Browsers look alike, so a non-browser UA from a workstation stands out right away.

---

## Benign (challenge, Splunk)

**Scenario:** the IDS flagged a host in one department as possibly compromised. You get Windows **process creation logs (Event ID 4688)** in Splunk and have to reconstruct what happened.

**What it practises:**
- Splitting users into departments from the provided lists and **spotting an account that shouldn't exist** (e.g. a lookalike/imposter username)
- Finding users running **system recon** commands they have no reason to run
- Spotting **scheduled task** persistence
- Catching a **LOLBin download** (e.g. `certutil -urlcache -f` fetching a payload from a file-hosting site) and identifying the file and URL
```spl
index=win_eventlogs EventID=4688
| stats count by UserName, HostName | sort count          # rare users first
index=win_eventlogs EventID=4688 (ProcessName="*certutil*" OR ProcessName="*schtasks*")
| table _time, UserName, HostName, CommandLine
```
**Lesson:** with only process creation logs you can still rebuild most of an attack: who ran what, when, from where, and what they downloaded. Sorting by **rare** values (`sort count` ascending) often finds the attacker faster than sorting by common ones.
