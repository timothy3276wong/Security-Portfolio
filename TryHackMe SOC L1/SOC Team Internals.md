# TryHackMe SOC Level 1 — SOC Team Internals

The module about what happens to an alert once it lands in the queue: how L1 triages it, writes it up, escalates it, and what context to pull in along the way. It finishes with how a SOC measures whether it's doing a good job.

**Rooms:** SOC L1 Alert Triage · SOC L1 Alert Reporting · SOC Workbooks and Lookups · SOC Metrics and Objectives · SOC Simulator: Introduction to Phishing

**Skills covered:** alert properties · prioritization · triage workflow · TP/FP verdicts · the 5 Ws report · escalation · identity/asset inventories · workbooks · MTTD / MTTA / MTTR · false positive rate

---

## SOC L1 Alert Triage

### Events vs. alerts
**Events** are raw records (a login, a process start, a file download) produced by firewalls, operating systems and cloud platforms. Security tools analyze millions of them and raise an **alert** only for the suspicious ones, so analysts work a queue instead of reading raw logs.

**Where alerts come from:** the **SIEM** (central log collection and correlation), **EDR/NDR** (endpoint or network detection, usually feeding the SIEM), **SOAR** (automated handling) and **ITSM** (alerts tracked as tickets).

### Alert properties
| Field | Meaning |
|---|---|
| Time | When the alert fired (shortly after the event) |
| Name | Short description of the detected activity |
| Severity | Low → Medium → High → Critical |
| **Status** | Where it is in the workflow: New → In Progress → Closed |
| **Verdict** | What it actually was: True Positive or False Positive |
| Assignee | Who owns it |
| Description | Why it fired, sometimes with triage hints |
| Fields | Username, hostname, command line, hash, etc. |

> **Status ≠ Verdict.** Status tracks progress. Verdict records the outcome. An alert can be Closed + True Positive.

### Prioritization
1. **Filter** out alerts already assigned or in progress.
2. **Sort by severity**, highest first.
3. **Sort by age** within the same severity, oldest first (it has had longer to do damage).

**Worked example.** Queue: (A) Medium, 09:10 · (B) High, 09:40 · (C) Medium, 08:55 · (D) High, 09:05 (already assigned)
→ Drop D. Work **B** first (High), then **C** (Medium, older), then **A**. Severity always beats age. Age only breaks ties.

### The triage workflow
1. **Initial actions:** assign the alert to yourself, set it to *In Progress*, read the name, description and key fields.
2. **Investigate:** work out which user, host or network is involved and what the suspicious action was. Check surrounding events, run indicators (hashes, IPs) through threat intel, and follow the relevant **workbook / playbook / runbook** if there is one.
3. **Final actions:** decide TP or FP, write a comment explaining why, and set it to *Closed*.

**Lessons from the lab alerts:**
- Context can explain an alert: a "suspicious" binary might just be a video-conferencing tool.
- **Double extensions** (`invoice.pdf.exe`) are classic masquerading. Check the hash.
- Downloads from a legitimate platform (e.g. GitHub) can still be flagged and still be fine. Judge by context.
- **Closing an alert doesn't stop an attack.** Containment and response are separate steps.

---

## SOC L1 Alert Reporting

After triage, an alert goes through three linked steps:
- **Reporting:** document findings in more depth than a one-line comment
- **Escalation:** hand real threats to L2 so they pick up where you left off
- **Communication:** coordinate with IT, HR or management when needed

### Why write reports
They give L2 context, keep the evidence after raw SIEM logs roll off retention, and force you to check your own reasoning, because gaps show up quickly once you write it down.

### The 5 Ws
| W | Answer with |
|---|---|
| **Who** | User, service account or process |
| **What** | Commands run, files downloaded, links clicked |
| **When** | Exact start and end timestamps |
| **Where** | Host, IP, cloud instance, URL |
| **Why** | Reasoning behind the verdict |

**Example report (phishing alert):**
> **Who:** j.smith@corp.local · **What:** received an email from `payroll@c0rp-hr.com` with `Salary_Update.zip`, opened the attachment, and `wscript.exe` spawned from Outlook · **When:** 2026-10-14 13:02–13:05 UTC · **Where:** WKS-FIN-07 (10.10.4.23) · **Why: True Positive.** Lookalike sender domain, SPF fail, urgent wording, and script execution after opening. Escalated to L2 for containment.

Keep reports short, factual and evidence-backed (log snippets, field values). **SPF/DKIM failures**, urgency and unexpected attachments are the usual phishing indicators.

### When to escalate
- It's a major attack needing deeper investigation or DFIR
- Remediation is needed (malware removal, host isolation, password reset)
- Someone outside the SOC must be told (customers, management, law enforcement)
- **You don't fully understand it.** Asking a senior is always better than closing something you're unsure about.

**How:** write the report, record the verdict, keep it *In Progress*, reassign it to the on-shift L2, and ping them directly.

### Communication under pressure
- L2 not answering on something urgent → try L2 directly, then L3, then the manager (follow the chain of command)
- Chat account might be compromised → verify **out of band** (e.g. a phone call), never over the same channel
- Alert flood → keep working in priority order, but tell L2 about the volume
- You think you closed a real attack earlier → tell L2 immediately. Attackers can sit dormant for weeks.
- SIEM logs unparsed or broken → don't skip the alert. Investigate as far as you can and report the tooling problem to L2 or engineering.

---

## SOC Workbooks and Lookups

Triage often needs context the alert doesn't include. **Lookups** supply it.

### Identity inventory: *who*
A catalogue of employees and service accounts: role, privileges, location, contacts. It tells you whether an action is normal for that person. Sources: Active Directory, SSO, HR systems, spreadsheets.

### Asset inventory: *where*
A list of servers and workstations with their role and sensitivity (e.g. "FS-02: finance file server", "DC-01: domain controller"). Sources: AD, SIEM/EDR, MDM, custom records.

Together they answer "is this normal business activity?" A finance user opening a finance share at 10 a.m. is expected. A service account logging into a workstation interactively is not.

### Network diagrams
These map subnets, servers, exposed services and the connections between them. Use them to place an IP in context (which subnet, what role), see what's exposed (e.g. VPN on 443), and rebuild an attack path.
*Example:* a brute-forced VPN login, then internal scanning that's blocked on one subnet but carries on in another, is a true positive with lateral movement.

### Workbooks
Also called playbooks, runbooks or workflows. They're step-by-step procedures written by seniors so L1 triages consistently. Most follow three blocks:

```
Enrichment     → identity/asset lookup, threat intel on IP/hash
Investigation  → SIEM search, user behaviour, is this expected?
Escalation     → close as FP (and tune) OR report + escalate to L2 / verify with user
```

**Example: "Unusual login location" workbook**
1. Assign the alert → 2. Look up the user (role, normal country, travel?) → 3. Check IP reputation (VPN/proxy/known bad?) → 4. SIEM: other logins from the same IP, impossible travel, MFA result → 5. Expected → close as FP. Unexplained → contact the user or escalate to L2.

Teams range from hundreds of detailed, near-automated workbooks to a few high-level ones that lean on analyst judgement. An L1 should be able to break an investigation into modular blocks like these.

---

## SOC Metrics and Objectives

### Core metrics
| Metric | Formula | What it tells you |
|---|---|---|
| **Alerts Count** | total alerts | Workload. Too many means missed threats, too few may mean a visibility gap. ~30/day per L1 is healthy |
| **False Positive Rate (FPR)** | FP ÷ total alerts | Noise. Above ~80% causes alert fatigue. Fix by tuning rules |
| **Alert Escalation Rate** | escalated ÷ total | L1 independence. Target <50%, ideally <20% |
| **Threat Detection Rate** | detected ÷ total threats | Reliability. Goal is 100% |

### Timing metrics (usually written into the SLA)
An **SLA** (Service Level Agreement) sets performance targets between the SOC and management, or between an MSSP and its clients. Coverage is usually 24/7. An 8/5 team won't see a Saturday alert until Monday.

| Metric | Measured from → to | Example SLA |
|---|---|---|
| **MTTD:** Mean Time to Detect | attack starts → alert created | 5 min |
| **MTTA:** Mean Time to Acknowledge | alert created → analyst starts triage | 10 min |
| **MTTR:** Mean Time to Respond | alert created → threat contained | 60 min |

**Worked example.** An attack starts at 14:00, the alert fires at 14:04, the analyst picks it up at 14:12, and the host is isolated at 14:50.
- MTTD = 4 min ✅ · MTTA = 8 min ✅ · MTTR = 14:50 − 14:04 = **46 min** ✅

**FPR example:** 900 alerts in a week, 810 closed as FP → FPR = 810/900 = **90%**. That's over the ~80% ceiling, so it's time to tune.

### Fixing bad metrics
| Problem | Fix |
|---|---|
| High FPR (>80%) | Exclude trusted activity (e.g. system updates) from rules, automate common triage with SOAR or scripts |
| High MTTD (>30 min) | Run detection rules more often, make sure logs arrive in near real time |
| High MTTA (>30 min) | Real-time alert notifications, spread alerts evenly across the shift |
| High MTTR (>4 h) | Escalate faster, document response runbooks (e.g. credential rotation) |

Managers usually own the metrics, but L1s are often the first to notice problems like noisy rules, and should raise them clearly. Improving metrics is a team effort.

---

## SOC Simulator: Introduction to Phishing

The first hands-on run in TryHackMe's **SOC Simulator**: a simulated SOC shift with a live alert queue of phishing-related alerts and a SIEM to investigate them in. It puts the rest of the module into practice:

- **Prioritize** the queue by severity, then age
- **Triage** each alert: check the sender domain and authentication results, links and attachments, then search the SIEM for whether anyone clicked or ran anything
- **Verdict:** classify each alert as TP or FP
- **Report:** write a case report for each alert (5 Ws style). The simulator scores both the verdicts and the quality of the write-ups

**Takeaway:** most alerts in the queue are benign. The skill is closing the noise quickly with a clear justification while still catching the one real phish, and writing it up well enough that L2 doesn't have to start over.
