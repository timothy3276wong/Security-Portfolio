# TryHackMe SOC Level 1 — Cyber Defence Frameworks

Frameworks that describe how attacks unfold and how to defend against them: the Pyramid of Pain, Cyber Kill Chain, Unified Kill Chain and MITRE, followed by two practical challenges that apply them.

**Rooms:** Pyramid of Pain · Cyber Kill Chain · Unified Kill Chain · MITRE · Summit · Eviction

**Skills covered:** IOC types & their value · attack lifecycle models · MITRE ATT&CK / D3FEND · purple-team detection · ATT&CK Navigator · mapping TTPs to detections

---

## Pyramid of Pain

The pyramid ranks indicators by **how much pain it causes the attacker when you detect and block them**. Lower levels are easy to block but just as easy for the attacker to change.

```
            ▲  TTPs                 ← tough: attacker has to change behaviour
           ▲▲  Tools                ← challenging
          ▲▲▲  Network/Host Artifacts ← annoying
         ▲▲▲▲  Domain Names          ← simple
        ▲▲▲▲▲  IP Addresses          ← easy
       ▲▲▲▲▲▲  Hash Values           ← trivial
```

| Level | Notes |
|---|---|
| **Hash values** | MD5 → SHA-1 → SHA-2 (increasing security). Identifies an exact malicious file, but changing one byte gives a new hash, so it's the weakest IOC |
| **IP addresses** | Block, drop or deny inbound requests from the IP. Attackers rotate IPs easily (or use fast flux) |
| **Domain names** | Slightly harder to change (registration costs time and money). Attackers rely on users trusting familiar-looking domains (lookalikes, punycode) |
| **Host artifacts** | Traces on the system: registry values, suspicious process execution, dropped files, patterns |
| **Network artifacts** | User-agent strings, C2 info, URI patterns. Detect with PCAPs in Wireshark/TShark or IDS logs |
| **Tools** | Malicious docs, backdoors, custom .exes, payloads. Detecting the tool forces the attacker to retool |
| **TTPs** | Tactics, Techniques & Procedures, i.e. the whole ATT&CK matrix. Detect *behaviour* and the attacker has to change how they operate |

In the lab I analyzed an Any.Run malware report to pull IOCs at each level.

---

## Cyber Kill Chain

Lockheed Martin's 7-stage model of an attack. Break any link and the later stages fail.

1. **Reconnaissance:** research and planning. OSINT is the big one. *Passive* (no contact with the target) vs. *active* (scanning, probing)
2. **Weaponization:** packaging the exploit and malware into a deliverable payload (e.g. a macro doc)
3. **Delivery:** getting it into the environment (phishing email, USB, watering hole)
4. **Exploitation:** the payload executes and exploits a vulnerability
5. **Installation:** a persistent backdoor so the attacker can come back
6. **Command & Control (C2):** the compromised host talks to the attacker's external server
7. **Actions on Objectives:** the end goal with full access: exfiltration, encryption, destruction

---

## Unified Kill Chain

A more complete model (18 phases) built for **threat modelling**, i.e. working out risk and which attacks you're exposed to. Unlike the Cyber Kill Chain, it covers what happens *after* the initial breach.

| Stage | Phases |
|---|---|
| **In** (initial foothold) | Reconnaissance, Weaponization, Delivery, Social Engineering, Exploitation, Persistence, Defense Evasion, Command & Control |
| **Through** (network propagation) | Pivoting, Discovery, Privilege Escalation, Execution, Credential Access, Lateral Movement |
| **Out** (actions on objectives) | Collection, Exfiltration, Impact, Objectives |

---

## MITRE

MITRE is a not-for-profit that does R&D across many domains "to solve problems for a safer world." Its security projects:

- **ATT&CK:** knowledge base of real-world adversary tactics and techniques (Tactic → Technique → Sub-technique, e.g. `T1059.001` PowerShell). Useful for both red and blue teams, and probably the most useful single resource in this module
- **D3FEND:** the defensive counterpart, a knowledge base of countermeasures mapped to the techniques they counter
- **ATLAS:** threats to AI and ML systems
- Others include CAR (analytics) and Engage (adversary engagement / deception)

---

## Summit

A **purple-team** lab: a simulated attacker runs malware samples, and you configure defences to detect and prevent each one, moving up the Pyramid of Pain:

1. **Block the hash:** works until the attacker recompiles
2. **Block the IP:** works until they switch servers
3. → domain → host/network artifacts → tools → **TTPs**

Each round the attacker changes the cheap indicator, which shows in practice why higher-level detections hold up longer.

---

## Eviction

**Scenario:** you're Sunny, a SOC analyst at E-corp, a rare earth metals manufacturer. Threat intel warns that **APT28** (Fancy Bear, linked to Russia's GRU, unit 26165, active since around 2004) is targeting organizations like yours. Your job is to use **MITRE ATT&CK Navigator** to profile the group, work out what to look for at each stage, and evict them if they're already inside.

### ATT&CK Navigator
A web tool that loads a threat group's known techniques as a **layer** over the ATT&CK matrix, colour-highlighting every technique the group has been seen using, organized by tactic. Instead of reading a long threat report, you get a visual checklist of what to hunt for.

```
Navigator → Create New Layer → Enterprise
→ search "APT28" under Threat Groups → select → techniques highlight
```

### APT28's playbook, by tactic
| Tactic | Technique | ID |
|---|---|---|
| Reconnaissance | Phishing for Information: Spearphishing Link | T1598.003 |
| Resource Development | Compromise Accounts: Email Accounts | T1586.002 |
| Execution | User Execution: Malicious Link / Malicious File | T1204.001 / .002 |
| Execution | Command & Scripting Interpreter: PowerShell / Windows Command Shell | T1059.001 / .003 |
| Persistence | Boot or Logon Autostart: Registry Run Keys | T1547.001 |
| Defense Evasion | System Binary Proxy Execution: Rundll32 | T1218.011 |
| Discovery | Network Sniffing (e.g. tcpdump) | T1040 |
| Lateral Movement | Remote Services: SMB/Windows Admin Shares | T1021.002 |
| Collection | Data from Information Repositories: SharePoint | T1213.002 |
| Command & Control | Proxy: External Proxy / Multi-hop Proxy | T1090.002 / .003 |

### Turning TTPs into detections
This is the point of the room: every highlighted technique becomes something to monitor.

| Technique | What to watch |
|---|---|
| Spearphishing link | Email gateway logs, URL clicks to newly registered domains |
| PowerShell / cmd | Process creation (4688 / Sysmon 1), Office apps spawning shells, encoded commands |
| Registry Run Keys | Writes to `HKCU\...\CurrentVersion\Run` (Sysmon 13) |
| Rundll32 | `rundll32.exe` loading DLLs from user-writable paths or making network connections |
| SMB admin shares | Access to `C$` / `ADMIN$`, 5140/5145 events, logons between workstations |
| SharePoint collection | Bulk downloads by one account |
| External proxy C2 | Beaconing to proxy or VPS infrastructure, unusual destinations |

### How it connects back to the module
- The **Pyramid of Pain** says TTPs sit at the top: they're the hardest thing for an attacker to change, so detecting *behaviour* (PowerShell from Word, Run key persistence) holds up better than blocking a hash or an IP.
- The **Kill Chain / UKC** order explains the table: break any early link (phishing, execution) and the later stages never happen.
- **Summit** practised detecting at each level of the pyramid. **Eviction** practises planning detections from threat intel *before* the attack shows up.
