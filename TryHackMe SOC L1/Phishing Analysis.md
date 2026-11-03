# TryHackMe SOC Level 1 — Phishing Analysis

Phishing is the most common way attackers get initial access, so it's also one of the most common alerts an L1 triages. This module covers how email works, what real phishing looks like, the tools used to analyze it safely, and the controls that stop it before it reaches anyone.

**Rooms:** Phishing Analysis Fundamentals · Phishing Emails in Action · Phishing Analysis Tools · Phishing Prevention

**Skills covered:** email protocols & headers · raw source & base64 attachments · phishing techniques · defanging · header/URL/file reputation tools · sandboxes · PhishTool · SPF / DKIM / DMARC / S/MIME · SMTP traffic in Wireshark

---

## Phishing Analysis Fundamentals

### Email address anatomy
```
billing.team @ paypal.com
└─ mailbox ─┘   └ domain ┘
```
The **domain** decides where mail gets routed (the street), and the **mailbox** picks the recipient (the house number). When checking a sender, the domain is what matters, since the display name and mailbox can be anything.

### Protocols & ports
| Protocol | Job | Ports (plain / TLS) |
|---|---|---|
| **SMTP** | *Sends* mail, client → server and server → server | 25 / 587 (STARTTLS), 465 |
| **POP3** | *Downloads* mail to one device (usually deleted from the server) | 110 / 995 |
| **IMAP** | *Syncs* mail across devices, keeps it on the server | 143 / 993 |

**Delivery flow:** sender's server looks up the recipient domain's **MX record** in DNS → SMTP hands the message over, possibly through several relays → it lands in the mailbox → the client pulls it with POP3 or IMAP.

### Headers
Every email is a **header** (metadata: who, when, which route) plus a **body**. Clients only show From / To / Subject / Date. The raw source shows the rest:

| Field | Why it matters |
|---|---|
| `X-Originating-IP` | The IP the message actually came from |
| `smtp.mailfrom` / `header.from` | Domains checked by SPF/DMARC. They should match |
| `Reply-To` | Where replies go. **If it differs from From, that's a red flag** |
| `Return-Path` | Where bounces go (envelope sender) |
| `Received:` | One per hop. Read **bottom → top** to trace the route |

Look up the sender IP (ARIN/WHOIS) to find the ISP or hosting provider.

### Body & attachments
Emails are rendered from HTML, so view the source to see real link targets and remote image sources. Attachments are MIME parts:
```
Content-Type: application/pdf; name="Invoice.pdf"
Content-Disposition: attachment; filename="Invoice.pdf"
Content-Transfer-Encoding: base64
JVBERi0xLjQKJ...
```
Decoding that base64 block (CyberChef → *From Base64* → save) gives back the original file, so you can examine it without opening the email.

### Types of phishing
- **Spam / MalSpam:** bulk junk. MalSpam carries a malicious payload
- **Phishing:** impersonates a trusted brand to steal info
- **Spear phishing:** aimed at a specific person or organization
- **Whaling:** spear phishing aimed at executives
- **Smishing / Vishing:** over SMS / voice calls
- **BEC (Business Email Compromise):** the attacker controls a *real internal account* and uses it to request payments or data. It's hard to spot because the sender checks out.

**Common indicators:** spoofed sender, urgent subject (invoice, suspension), copied brand HTML, poor grammar, generic greeting ("Dear customer"), hidden or shortened links, attachments disguised as documents.

**Safe handling:** never click links or open attachments, and **defang** indicators before sharing them.

---

## Phishing Emails in Action

Real phishing samples, each showing a technique:

| Sample | Techniques |
|---|---|
| **PayPal** "order cancelled" | Display name says PayPal but the domain is unrelated. The recipient doesn't match. The "Cancel order" button is a **shortened URL** leading off-brand |
| **Package tracking** | Fake tracking number for legitimacy. A hidden **tracking pixel** (remote image) tells the attacker the email was opened. Link text ≠ real destination |
| **OneDrive / Adobe doc share** | "Link expires today" urgency, fake SharePoint login page, **credential harvesting** with a fake "wrong password" error so the victim types it twice |
| **Netflix** billing | "Account suspended" threat, brand misspelled, the payload is a PDF attachment, phone number from the wrong region |
| **Apple** receipt | Victim is in **BCC** (the To field is a decoy), empty body, odd **.dot** (Word template) attachment |
| **DHL** shipping | Copied HTML, broken "view as web page" link, Excel attachment that tries to run `regasm.exe` (a legitimate .NET tool abused to run code, i.e. **living off the land**) |

**Tracking pixels:** a 1×1 image like `<img src="http://evil.tld/Tracking.png?id=victim42">`. Loading it confirms the address is live and records when it was opened. This is why many clients block remote images by default.

### Defanging
Make indicators unclickable before putting them in a ticket or report:
```
https://login.micros0ft-support.com/auth   →   hxxps[://]login[.]micros0ft-support[.]com/auth
185.243.115.84                             →   185[.]243[.]115[.]84
attacker@evil.com                          →   attacker[@]evil[.]com
```
(CyberChef has *Defang URL* / *Defang IP Addresses* recipes.)

**Root domain:** what controls the link is the registered domain just before the TLD. `paypal.com.secure-login.ru/...` is controlled by `secure-login.ru`, not PayPal.

**Takeaway:** almost every sample combines a **spoofed sender**, **urgency**, **brand impersonation**, and **one interactive element** (a link or attachment) carrying the real attack.

---

## Phishing Analysis Tools

### What to collect
| From the header | From the body |
|---|---|
| Sender address & **sender IP** (+ reverse DNS) | All URLs (expand shortened ones) |
| Reply-To, Return-Path | Attachment names |
| Recipients (incl. CC/BCC) | **Attachment hashes** (SHA-256) |
| Subject, date/time | |

### Header analysis
- **Google Admin Toolbox Messageheader:** relay hops, delays, misconfigurations
- **Microsoft Message Header Analyzer (MHA)** and **mailheader.org:** parse raw headers into readable fields

Different tools surface different fields, so cross-check them.
**MTA** (Message Transfer Agent) = server that relays mail. **MUA** (Mail User Agent) = the client (Outlook, Gmail).

### URL & IP reputation
| Tool | Use |
|---|---|
| **IPinfo.io** | Geolocation and owner of an IP |
| **URLScan.io** | Loads the URL in a sandbox: screenshot, contacted domains/IPs, flags brand impersonation |
| URL2PNG / Wannabrowser | Safe screenshots / previews |
| **Cisco Talos** | IP / domain / URL / file reputation |
| CyberChef *Extract URLs*, URL Extractor | Pull every link out of raw source |

Check both the full URL and the **root domain**, because their reputations can differ.

### Attachments
Save the file without opening it, then hash it:
```bash
sha256sum Invoice.pdf
# 3f7a...e91c  Invoice.pdf   → paste into VirusTotal / Talos / ReversingLabs
```
A hash lookup tells you if the file is known malware **without uploading or running it**.

### Sandboxes
Run the file in isolation and watch what it does: domains contacted, second-stage downloads, persistence, registry and file changes, IOCs.
- **Any.Run:** interactive, so you can watch and click in a live VM
- **Hybrid Analysis:** free static + dynamic analysis
- **Joe Sandbox:** deep reports with ATT&CK mapping, YARA/Sigma matches, execution graphs

### PhishTool
Upload an `.eml` and it parses everything in one view: sender/recipient, originating IP + rDNS, the SMTP relay chain, X-headers, text and HTML bodies, extracted URLs, and attachment hashes with VirusTotal results (with an API key). You then **resolve** the case with a verdict, notes and a classification (e.g. *Whaling*).

### Workflow from the case exercises
```
1. Identify the impersonated brand
2. Header tool → From, Reply-To, originating IP, relay domains (e.g. X-Relaying-Domain)
3. Extract + expand URLs (t.co, bit.ly) → URLScan / Talos
4. Hash attachments → VirusTotal; if unknown → sandbox
5. Sandbox report → verdict, malicious connections, DNS requests, CVEs exploited
6. Defang every IOC before writing it up
```
Other tools: **MXToolbox** (DNS/blocklist checks), **PhishTank** (reported phishing URLs), **Spamhaus** (blocklists), **eml_analyzer**.

---

## Phishing Prevention

**In short:** SPF checks *where* mail came from, DKIM checks *what* was sent, and DMARC says *what to do* when they fail.

### SPF (Sender Policy Framework)
A DNS TXT record listing which servers may send mail for a domain. The receiver checks the connecting IP against it.
```
v=spf1 ip4:203.0.113.10 include:_spf.google.com -all
```
| Part | Meaning |
|---|---|
| `v=spf1` | This is an SPF record |
| `ip4:` | Authorized IP |
| `include:` | Also trust whoever *that* domain's SPF authorizes (e.g. Google Workspace) |
| `-all` | Everything else **fails** (`~all` = softfail, `?all` = neutral) |

**Results:** `pass` · `fail` (unauthorized, usually rejected) · `softfail` (accepted but marked suspicious) · `neutral` / `none` (no verdict, or no record) · `temperror` / `permerror` (DNS problem / broken record).

**Example:** mail claiming `@corp.com` arrives from `198.51.100.7`, which isn't in the record and the record ends in `-all`, so `spf=fail`.

**Limitation:** SPF checks the *envelope* sender (Return-Path), not the From header the user sees, and it breaks on forwarding. DMARC fixes the first problem.

### DKIM (DomainKeys Identified Mail)
The sending server **signs** selected headers and the body with a private key. The receiver fetches the public key from DNS (`selector._domainkey.domain`) and verifies the signature. A pass proves the domain sent it **and** that it wasn't modified in transit.
```
v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEB...
```
Because it's tied to the content rather than the IP, DKIM usually survives forwarding. A `permerror` such as "no key for signature" means the public key couldn't be found or the record is broken.

### DMARC
Published at `_dmarc.domain`. It requires **alignment**: the domain in the visible **From** header must match the domain that passed SPF *or* DKIM. That's what stops a "valid SPF for evil.com, From: paypal.com" trick.
```
v=DMARC1; p=reject; rua=mailto:dmarc-reports@corp.com
```
| Policy | Effect on failing mail |
|---|---|
| `p=none` | Monitor only (still delivered, reports sent) |
| `p=quarantine` | Send to spam |
| `p=reject` | Refuse it. Strongest protection |

Domains usually move `none → quarantine → reject` as they confirm that all their legitimate senders pass.

**Reading it in a header:**
```
Authentication-Results: mx.google.com;
   spf=pass smtp.mailfrom=bounce.mailer-xyz.com;
   dkim=pass header.d=mailer-xyz.com;
   dmarc=fail (p=REJECT) header.from=paypal.com
```
→ SPF and DKIM passed, but for **mailer-xyz.com**. Neither aligns with `paypal.com` in From, so DMARC fails. This is a spoofed PayPal email.

### S/MIME
Works on individual messages rather than whole domains, using certificates from a CA:
- **Signing** (sender's private key → verified with their public key): authentication, integrity, non-repudiation
- **Encryption** (recipient's public key → only their private key decrypts): confidentiality

It complements SPF/DKIM/DMARC rather than replacing them. One downside: encrypted mail can't be inspected by the security gateway.

### SMTP traffic in Wireshark
```
smtp                          # all SMTP
smtp.response.code            # packets carrying a response code
smtp.response.code eq 553     # a specific code
imf                           # parsed email messages (Internet Message Format)
```
| Code | Meaning |
|---|---|
| 220 | Service ready (server greeting) |
| 250 | OK |
| 552 | Action aborted. Formally "storage exceeded", but in the lab the server's text showed a security block |
| 553 | Mailbox name not allowed. In the lab, rejected because of a Spamhaus listing |

In `imf` packets, check **`X-Mailer`** (the sending client), `Content-Transfer-Encoding` (base64 attachments), and attachment names. A `.scr` (screensaver, which is really an executable) is a big red flag. Use *Find Packet → String* to search for text like "spamhaus".

### How organizations stop phishing
| Technical | User-focused |
|---|---|
| Reputation-based email filtering | "**External sender**" warning banners |
| Secure Email Gateway (spoofing/impersonation detection) | One-click "Report phish" button |
| **Link rewriting** (URL scanned again at click time) | Awareness training + simulated phishing |
| **Attachment sandboxing** | |
| SPF + DKIM + DMARC `p=reject` | |
