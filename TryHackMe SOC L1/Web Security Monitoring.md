# TryHackMe SOC Level 1 — Web Security Monitoring

Web apps run all the time, face the internet, and connect straight to databases, which makes them one of the most common ways in. This module covers how the web stack is defended, then how to detect the three big web threats: **injection-style attacks**, **web shells** and **DDoS**. Each uses three data sources: logs, traffic and the WAF.

**Rooms:** Web Security Essentials · Detecting Web Attacks · Detecting Web Shells · Detecting Web DDoS

**Skills covered:** web stack layers · defence in depth · CDN & WAF · client- vs. server-side attacks · access log analysis · network-based detection · web shell indicators · DoS/DDoS types & log patterns · SIEM queries for web data

---

## Web Security Essentials

### Why the web
Software moved from desktop programs to browser-based services. That brought global reach and instant updates, but every app is now internet-facing, and one flaw can expose a whole backend database.

### The three layers (and what protects each)
| Layer | What's there | Key protections |
|---|---|---|
| **Application** | Code, APIs, sessions | Input validation, output encoding, parameterized queries, MFA, secure sessions + anti-CSRF tokens, safe error messages, RBAC/ABAC + least privilege |
| **Web server** | Apache, Nginx, IIS | Hide version banners, disable unused modules, strong TLS, detailed logging |
| **Host** | OS, containers, VMs | Minimal services, closed ports, strict file permissions, kernel security modules (SELinux/AppArmor), patching |

**Security headers** (application layer): `Content-Security-Policy` (what scripts can load), `Strict-Transport-Security` (HTTPS only), `X-Frame-Options` (no framing, so no clickjacking), `X-Content-Type-Options: nosniff`.

### Defence systems in front of the app
- **CDN** (Cloudflare, Akamai): absorbs and filters traffic at the edge, mitigates DDoS, manages bots, terminates TLS
- **WAF** (Web Application Firewall): inspects HTTP requests *before* they reach the app using signatures, heuristics, ML and IP reputation. Runs on the same host or as a separate layer in front
  - Example rules: block SQLi/XSS patterns · rate-limit per IP · geo-block · allow trusted bots · watch responses for data leakage
- **EDR / sandboxing / threat intel** on the hosts behind it

**Takeaway:** defence in depth. No single layer is trusted to stop everything.

---

## Detecting Web Attacks

### Client-side vs. server-side
| | Client-side | Server-side |
|---|---|---|
| Target | The user's browser | The server, app code, backend |
| Examples | **XSS**, **CSRF**, clickjacking | **SQLi**, **command injection**, brute force, path traversal |
| SOC visibility | Low (runs in the victim's browser) | High (requests hit your logs) |

### Log-based detection
**Apache/Nginx combined log format:**
```
10.10.1.50 - - [08/Nov/2026:02:14:07 -0500] "GET /products.php?id=1' OR '1'='1 HTTP/1.1" 200 5320 "-" "sqlmap/1.7.2"
└ client IP ┘   └──── timestamp ────┘        └──── method + URI ───────────────┘  └status┘└size┘ └ref┘ └─ user agent ─┘
```
| Pattern | What it means |
|---|---|
| Many `404`s from one IP in seconds | Directory brute force / scanning (gobuster, dirb) |
| Many `POST /login` → `401/200` | Credential brute force. A size change in the response shows the one that succeeded |
| `' OR 1=1`, `UNION SELECT`, `SLEEP(` in the URI | **SQL injection** |
| `<script>`, `onerror=`, `%3Cscript%3E` | **XSS** |
| `../../etc/passwd`, `%2e%2e%2f` | **Path traversal / LFI** |
| `;id`, `\|whoami`, `$(...)` | **Command injection** |
| UA = sqlmap, Nikto, Nmap, Hydra | Automated tooling |

> **Decode first:** attacks are usually URL-encoded (`%27` = `'`, `%20` = space). CyberChef → *URL Decode* before judging.

**Response size is a big clue:** a `200` that's much larger than normal after a SQLi attempt suggests data came back.

**Log limitations:** access logs usually **don't record POST bodies** (so no submitted credentials or injected form data) and may truncate query strings.

### Network-based detection
PCAPs show **everything**: full headers, POST bodies, cookies, uploaded files. The trade-off is that **HTTPS hides it** unless you have the keys or capture after TLS termination (e.g. at the load balancer).
```
http.request.method == "POST" && urlencoded-form
http.request.uri contains "UNION"
http.user_agent contains "sqlmap"
```

### WAF
Sits inline and decides allow / block / challenge (CAPTCHA). Rule types: known attack patterns, known-bad sources (threat intel), custom rules, rate limiting. **WAF logs are a third data source:** a block tells you an attack happened even when the app logs look clean.

**Correlate all three:** access log (what was requested) + PCAP (the full payload) + WAF (what was blocked) = the full story.

---

## Detecting Web Shells

A **web shell** is a malicious script (PHP, ASPX, JSP) that an attacker places on a web server so they can run commands through HTTP requests. It gives **persistence** (ATT&CK T1505.003) and is often the first foothold after an upload or RCE vulnerability.

### Anatomy
The smallest possible PHP web shell:
```php
<?php system($_GET['cmd']); ?>
```
Visiting `/uploads/img.php?cmd=whoami` runs `whoami` on the server and returns the output. Real ones add passwords, file managers and obfuscation (`eval(base64_decode(...))`, `str_rot13`, `gzinflate`).

**How they get there:** unrestricted file upload, RCE/injection, vulnerable CMS plugins, stolen admin/FTP credentials.

### Log-based detection
| Indicator | Example |
|---|---|
| A **POST** (or the first ever request) to a new script in an upload/image dir | `POST /uploads/avatar.php` |
| Command-like parameters | `?cmd=`, `?exec=`, `?c=whoami` |
| An upload request followed by requests to that same file | `POST /upload.php` → `GET /uploads/shell.php` |
| A single IP that only ever hits one obscure file | No referrer, no CSS/JS/image loads (not a real browser) |
| Unusual user agents, or responses that vary a lot in size | Command output returned |

### Beyond logs
- **File system:** new or recently modified script files in the web root
  ```bash
  find /var/www/ -name "*.php" -mtime -2          # changed in the last 2 days
  grep -rlE "eval\(|base64_decode|system\(|shell_exec" /var/www/
  ```
  Also: scripts in directories that should only hold images, odd file owners and permissions. File integrity monitoring and **YARA** rules help here.
- **Process tree (EDR):** the **web server process spawning a shell** is the strongest signal
  ```
  apache2 / httpd / w3wp.exe  →  sh / bash / cmd.exe / powershell.exe
  ```
  A web server has no normal reason to run `whoami`, `net user` or `ipconfig`.
- **Network:** outbound connections *from* the web server (reverse shells, downloading tools), plus the HTTP traffic carrying commands and output

### Investigating
Find the shell → work out **how it was uploaded** (the request right before it appeared) → list **every command run** through it (access logs + EDR) → check for further persistence or lateral movement → contain (isolate the host, remove the shell, patch the upload flaw, rotate credentials).

---

## Detecting Web DDoS

- **DoS:** one source overwhelms a service
- **DDoS:** many sources at once (usually a **botnet**), so blocking one IP doesn't help

It's an attack on **Availability** in the CIA triad.

### Types
| Layer | Example | Target |
|---|---|---|
| **Volumetric** (L3/4) | UDP/DNS amplification floods | Bandwidth |
| **Protocol** (L4) | SYN flood | Server connection tables |
| **Application** (L7) | **HTTP GET/POST floods**, **Slowloris** (holds connections open with slow, partial headers), hitting expensive pages (search, login) | Web server / app resources |

L7 attacks are the hardest to spot because each request looks legitimate.

**Motives:** hacktivism, extortion ("pay or we keep you offline"), competition, and **distraction** (a DDoS as cover while the real intrusion happens elsewhere).

### Log analysis
| Signal | Meaning |
|---|---|
| Requests per second far above baseline | Flood |
| Huge numbers of requests to **one URI** | L7 flood on an expensive page |
| Many IPs with **the same user agent** or identical request pattern | Botnet |
| Surge in **`503 Service Unavailable` / `504`** | The server is falling over |
| Many long-lived connections with tiny byte counts | Slowloris |
| Traffic from unusual countries or ASNs | Botnet geography |

**Worked example:** baseline is ~50 req/min. At 02:00 the log shows 12,000 req/min to `/search.php`, from 3,400 different IPs that all have the same user agent `Mozilla/5.0 (compatible)`, with 503s starting at 02:03. That's an L7 HTTP flood from a botnet.

### Leveraging the SIEM (Splunk)
```spl
index=web sourcetype=access_combined
| timechart span=1m count                                   # spot the spike

index=web | stats count by clientip | sort -count | head 20 # top talkers

index=web status=503 | timechart span=1m count              # when it started failing

index=web uri="/search.php" | stats dc(clientip) as unique_ips, count by useragent
```

### Defence
- **CDN / DDoS protection service** to absorb volume at the edge
- **Rate limiting** per IP or session, either on the WAF or the server
- **WAF rules / challenges** (CAPTCHA, JS challenge) to filter bots
- **Geo or ASN blocking** during an attack
- Server tuning: connection timeouts (counters Slowloris), caching of expensive pages, autoscaling
- An incident plan: who calls the ISP/CDN, and when to escalate
