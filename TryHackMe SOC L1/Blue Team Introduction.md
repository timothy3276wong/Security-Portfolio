# TryHackMe SOC Level 1 — Blue Team Introduction

The first module of the SOC Level 1 path. It explains what a SOC analyst actually does, where the SOC sits inside a company's security structure, and the two things attackers go after to get in: **people** and **systems**.

**Rooms:** Junior Security Analyst Intro · SOC Role in Blue Team · Humans as Attack Vectors · Systems as Attack Vectors

**Skills covered:** SOC roles & hierarchy · alert-to-escalation workflow · social engineering · vulnerabilities vs. misconfigurations · supply chain attacks · mitigation vs. detection

---

## Junior Security Analyst Intro

A Junior Security Analyst is the same job as a **SOC L1 Analyst**, the first line of defence. The day-to-day work is monitoring and investigating alerts, working in a 24/7 shift rotation, helping improve detections, and keeping up with new attack techniques.

**What the SOC protects:** intellectual property, employee data, business systems and brand reputation. The SOC monitors, investigates, prevents and responds around the clock.

**Who's on the team:**

| Role | What they do |
|---|---|
| L1 / Junior Analyst | Triage alerts, escalate anything real or unclear |
| Senior Analyst (L2) | Takes complex cases after L1's first pass, mentors juniors |
| SOC Engineer | Maintains tools and tunes alert rules. Doesn't work shifts or triage |
| SOC Manager | Runs operations, reports to leadership |
| Incident Responder | Called in on demand for major incidents |

**Simulation: a day on shift.** The lab walks through the core loop you repeat all day:

1. **Monitor:** spot a suspicious entry in the SIEM alert log (e.g. an unauthorized connection attempt).
2. **Investigate:** pull out the indicator (the source IP) and check its reputation with a threat intel tool.
3. **Escalate:** send the confirmed event to the person who decides next steps (here, the SOC team lead), not to whoever happens to be around.
4. **Respond:** block the malicious IP on the firewall.

---

## SOC Role in Blue Team

**Security priorities depend on the business.** A law firm cares most about document confidentiality, a factory about production staying up (availability), and a hospital about patient safety. The security structure should follow what the business needs.

**Reporting chain (large org):**
```
SOC Analyst → SOC Manager → CISO → CEO
```
The **CISO** (Chief Information Security Officer) oversees three branches:
- **Red Team:** offensive work such as pentesting and ethical hacking
- **Blue Team:** defensive work such as the SOC and incident response
- **GRC:** governance, risk and compliance (policies, audits, regulations)

Small companies often fold all of this into one IT/InfoSec team.

**Inside the Blue Team:**
- **SOC:** the first line. Handles alerts, investigates, and configures detection tools (L1, L2, engineers, manager).
- **CIRT / CSIRT** (Cyber Incident Response Team): brought in for critical or out-of-control incidents. Forensics experts, threat hunters, malware analysts and threat intel people. They can work without the SOC's usual tooling. Examples: JPCERT, Mandiant, AWS CIRT.
- **Specialists** (in bigger or tech-heavy orgs): digital forensics analyst, threat intel analyst, AppSec engineer, AI security researcher.

**Internal SOC vs. MSSP:**

| | Internal SOC | MSSP (Managed Security Service Provider) |
|---|---|---|
| Protects | One organization | Many client organizations |
| Pace | Calmer, fewer major attacks | Fast, high alert volume |
| Tools | Fewer tools, deeper expertise | Many tools, broad exposure |
| Who uses it | Larger companies | Smaller companies that can't staff their own SOC |

**Career path:** the natural step after L1 is **L2**. Other branches are SOC engineering, CIRT, or management, which can lead to CISO. Spend the first 1–2 years getting real experience and finding out what you enjoy.

**Final challenge: matching incidents to roles.** Brute force on the firewall → L1. Malware from a phishing email → L2. Ransomware outbreak → CERT lead. PCI DSS audit → GRC auditor. Web app assessment → pentester. SIEM falling over from full storage → SOC engineer. Tracking a named threat group → threat researcher.

---

## Humans as Attack Vectors

**Core idea:** people are the weakest link, and attackers are mostly after **access**. Tricking an employee is usually easier than breaking a hardened firewall. One compromised user can open up mailboxes, databases, banking sessions or, through a privileged account, the core network.

**What makes social engineering work:** the attack needs to look **trustworthy** (it seems to come from someone legitimate) and be **emotionally charged** (urgency, fear, curiosity).

**Common attacks on people:**
- **Phishing:** messages that get you to click, open an attachment, or enter credentials
- **Malware lures:** fake sites, fake CAPTCHAs, QR codes, SEO poisoning (malicious results pushed up in search rankings)
- **Deepfakes:** AI-generated voice or video of an executive asking for a wire transfer
- **Impersonation:** posing as IT, a colleague or a partner, often over the phone
- **Other:** USB drops, insider threats, physical intrusion, fake job offers

**Defence has two halves:**
- **Mitigation** lowers the odds and impact of an attack: anti-phishing email filters, AV/EDR to block execution, awareness training plus phishing simulations, and **"trust but verify"** (confirm unusual requests through a *separate* channel).
- **Detection** catches what gets past mitigation. **This is the SOC's main job.** No mitigation is perfect, so detection never stops mattering.

A SOC analyst should also recommend mitigations, since every phish the filter blocks is one fewer alert to triage.

**Practice scenarios:** triaging a suspicious download, spotting phishing red flags (urgent tone, unrealistic amounts, archive attachments, lookalike domains), verifying a possible CEO impersonation, and responding to a login that suggests stolen credentials (disable the account until the user is verified).

**Example: which controls actually stop social engineering?**
- ✅ Ongoing awareness training, a documented verification process for IT support requests, anti-phishing filtering plus AV
- ❌ Manually approving every login, blocking most of the internet, vulnerability scanning on its own (it doesn't address people)

---

## Systems as Attack Vectors

A **system** is anywhere data lives: a physical server, a VM or a cloud platform. User training can't stop an attack that goes straight at a weak system. Compromising one server that hosts many accounts beats phishing one person, so attackers prioritize high-value systems. Once they have a foothold, **lateral movement** lets them pivot between systems and escalate privileges until they reach the real target.

**Three main ways in:**
1. **Human-led:** malicious USBs, pirated software with malware, password reuse. Weak or stolen credentials show up in a large share of breaches.
2. **Vulnerabilities:** software flaws, default credentials, exposed legacy systems.
3. **Supply chain:** compromise a trusted library, component or update, and the malware reaches every customer. Examples: **SolarWinds**, **3CX**.

### Vulnerabilities
- **Zero-day:** attackers know about the flaw before a fix exists.
- **CVE:** the public ID a vulnerability gets once disclosed. That starts a race between attackers building exploits and defenders patching.
- **The real fix is the vendor patch.** Until one exists: restrict access to trusted IPs, apply vendor workarounds, and block known exploit patterns with a firewall, IPS or WAF.

### Misconfigurations
These are setup mistakes, not code bugs, usually made for convenience (default or weak passwords, a public cloud bucket, an exposed database). **Patching doesn't fix them; correcting the configuration does.** A badly configured service on the internet can be found by automated scanners and compromised within days.

Proactive checks:
- **Penetration testing:** an authorized simulated attack
- **Vulnerability scanning:** finds default creds, open ports, outdated services
- **Configuration audits:** compare settings against benchmarks like **CIS**

**Vulnerability vs. misconfiguration, worked example:**
| Finding | Type | Fix |
|---|---|---|
| Firewall running firmware with a known RCE CVE | Vulnerability | Patch (restrict mgmt access until then) |
| Admin panel on the internet with `admin:admin` | Misconfiguration | Change credentials, remove public exposure |
| Trusted vendor update starts beaconing out | Supply chain | Roll back the update, investigate |

**A good remediation plan includes:** a defined patch process, individual accounts instead of shared ones, AV on every host, strong generated passwords for privileged accounts, and regular IT security training. Hiding server names or taking the company website offline are not real fixes.

**Takeaway:** SOC analysts usually don't manage systems themselves, but knowing how systems get attacked, and passing that on to IT, is part of the job. Useful feeds: the **CISA KEV** (Known Exploited Vulnerabilities) catalog, vendor threat reports, and supply chain attack news.
