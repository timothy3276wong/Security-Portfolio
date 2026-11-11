# TryHackMe SOC Level 1 — Threat Analysis Tools

Almost every alert contains an indicator: a file hash, an IP, a domain. This module covers how to **enrich** those indicators with threat intelligence so you can reach a verdict, using one repeatable workflow: **verify → enrich → decide**.

**Rooms:** Intro to Cyber Threat Intel · File & Hash Threat Intel · IP & Domain Threat Intel · Invite Only (challenge)

**Skills covered:** data vs. information vs. intelligence · CTI types & lifecycle · STIX/TAXII · Diamond Model · suspicious paths & filenames · VirusTotal, MalwareBazaar · sandbox reports & their limits · WHOIS, DNS, TLS enrichment · ASN & geolocation · Shodan/Censys · VPN/proxy/Tor detection · multi-source verdicts

---

## Intro to Cyber Threat Intel

**CTI** = evidence-based knowledge about adversaries (who they are, what they want, how they operate) that you can use to defend and to make decisions.

### Data → information → intelligence
| Level | Example |
|---|---|
| **Data** | `185.220.101.4` |
| **Information** | That IP made 400 failed SSH logins on our servers last night |
| **Intelligence** | It's a Tor exit node used by a botnet that's spraying SSH across our sector. Block Tor at the edge and enforce SSH keys |

### Types of intelligence
| Type | Audience | Example |
|---|---|---|
| **Strategic** | Executives | "Ransomware against manufacturers is up. Budget for backups and EDR" |
| **Operational** | Security leads | Who is likely to target us, why, and which assets |
| **Tactical** | Detection engineers | Adversary TTPs → new detection rules |
| **Technical** | SOC / tooling | IOCs (hashes, IPs, domains) → blocklists, SIEM lookups |

**Sources:** internal (our own logs, incidents, assessments), community (forums, ISACs), external (commercial and open-source feeds, government advisories, vendor reports).

### CTI lifecycle
1. **Direction:** what do we need to know? Which assets matter most?
2. **Collection:** gather from feeds, logs, OSINT
3. **Processing:** parse, normalize, correlate (often in the SIEM)
4. **Analysis:** find IOCs and patterns, decide on actions
5. **Dissemination:** tailor the output (exec summary vs. IOC list)
6. **Feedback:** was it useful? Refine the process

### Standards & frameworks
- **STIX:** a structured *language* for describing threat intel (indicators, TTPs, campaigns, actors, and how they relate)
- **TAXII:** the *transport* protocol for sharing STIX. **Collection** model = clients pull from a server. **Channel** model = the server pushes to subscribers
- **MITRE ATT&CK:** a shared vocabulary for TTPs
- **Cyber Kill Chain / Unified Kill Chain:** attack stages
- **Diamond Model:** every intrusion has four connected parts. Knowing one lets you **pivot** to the others
```
            Adversary
           /         \
  Infrastructure — Capability
           \         /
             Victim
```
*Example:* a phishing domain (infrastructure) → WHOIS shows the same registrant email → other domains registered with it → a known actor (adversary) → their usual malware (capability).

---

## File & Hash Threat Intel

### 1. Verify: does the path and name look right?
**Suspicious locations** (user-writable, rarely hold legitimate programs):
```
C:\Users\Public\    C:\ProgramData\    C:\Windows\Temp\    %APPDATA%    %TEMP%    the root of C:\
```
**Filename heuristics:**
| Trick | Example |
|---|---|
| Double extension | `Invoice.pdf.exe` |
| Impersonating a system binary | `svch0st.exe`, `scvhost.exe`, or a real name in the wrong folder (`C:\Users\Public\svchost.exe`) |
| High-entropy / random name | `a8f3kq2z.exe` |
| Masquerading as an updater/tool | `GoogleUpdate.exe` in `AppData\Local\Temp` |

> The real `svchost.exe` only lives in `C:\Windows\System32\`. **The same name in a different path is a red flag on its own.**

### 2. Enrich: hash it and look it up
```powershell
Get-FileHash .\sample.exe -Algorithm SHA256      # PowerShell
certutil -hashfile sample.exe SHA256             # cmd
sha256sum sample.exe                             # Linux
```
Use **SHA-256** (MD5 and SHA-1 have known collisions but are still used for lookups).

**VirusTotal triage table:**
| Section | What to check |
|---|---|
| Detection | Ratio (e.g. 52/72) **and** the labels engines agree on (family name) |
| Details | File type, signer/certificate, compile time, **first submission date** |
| Relations | Contacted domains/IPs, dropped files, parent files |
| Behaviour | Sandbox actions, MITRE techniques |
| Community | Comments, YARA/Sigma hits |

**MalwareBazaar** (abuse.ch): search `sha256:<hash>`. Gives the malware **family tag**, YARA matches, campaign context and a downloadable sample (for analysts).

**How to read the result:**
- **High detections + a consistent family name** → malicious, and now you know its TTPs
- **0 detections** ≠ clean. It could be new, targeted, or never uploaded → go to a sandbox
- **Signed by a trusted vendor, years old, millions of sightings** → probably legitimate. Check the path still makes sense

### 3. Sandbox analysis
**Hybrid Analysis**, **Joe Sandbox**, Any.Run: confirm the file actually runs maliciously, pull **runtime IOCs** (C2 domains, dropped files, registry keys), and **map behaviour to ATT&CK**.

**Limitations:** evasion (sleeps, VM checks), short run times, encrypted C2 you can't read, and **fileless/LotL** malware that leaves little for the sandbox to see.

---

## IP & Domain Threat Intel

### Domain enrichment
| Check | Red flag |
|---|---|
| **WHOIS age** | Registered days ago (phishing domains are usually brand new) |
| Registrar / privacy | Cheap or abuse-friendly registrar, everything redacted |
| **DNS records** | A records on bulletproof hosting, frequent IP changes (fast flux), missing MX on a "company" domain |
| **TLS certificate** | Free cert issued minutes after registration, lookalike names in the SAN list (via crt.sh / certificate transparency logs) |
| Name itself | Typosquats, brand + keyword (`microsoft-login-verify.com`), odd TLDs |

### IP enrichment
- **ASN** (Autonomous System Number): *who owns the network*. A residential ISP, a big cloud (AWS/Azure/GCP), a CDN, or a known bulletproof host point to very different conclusions
- **Geolocation:** useful context (e.g. a login from a country with no staff), but **easily faked** with VPNs and cloud regions
- **Reputation:** AbuseIPDB, VirusTotal, Talos. Check report counts and *how recent* they are. Cloud IPs get reassigned, so old reports may be about someone else

### Service exposure
**Shodan** and **Censys** show what an IP is running to the internet:
- Open RDP/SMB/Telnet, admin panels → a likely compromised or attacker box
- **C2 framework fingerprints** (Cobalt Strike, Sliver default certs and banners) → attacker infrastructure
- A self-signed cert with a generic subject on 443 → worth a closer look

### VPN / proxy / Tor
**IP2Proxy**, **Spur**, and the public **Tor exit node** list tell you whether an IP is anonymized. This changes the verdict:
- An admin login from a commercial VPN might be a travelling employee, or stolen credentials
- **Tor** for corporate logins is almost never legitimate
- Anonymized IPs make **blocking by IP pointless**, so focus on the account instead (reset, MFA)

### Don't trust a single verdict
**Worked example:** `login-0ffice365.com` → WHOIS: registered 2 days ago · DNS: A record on a small VPS provider · TLS: certificate issued yesterday · VirusTotal: 3/90 detections · urlscan: Microsoft login page clone.
→ Each signal is weak on its own. **Together it's a confident phishing verdict**, even though most engines still mark it clean.

---

## Invite Only (challenge)

You get a set of flagged artefacts and have to **turn them into usable threat intel**: enrich each hash, IP and domain with the module's tools, connect them (Diamond Model-style pivoting), and summarize what the threat is and what to block.

**Workflow it reinforces:**
```
Verify   → does the path/name/context look wrong?
Enrich   → hash: VirusTotal, MalwareBazaar, sandbox
           IP:   ASN, reputation, Shodan/Censys, VPN/Tor check
           domain: WHOIS age, DNS, TLS cert, urlscan
Decide   → combine the signals → verdict + IOC list + recommended action
```
