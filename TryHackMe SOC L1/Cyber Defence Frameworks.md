# TryHackMe SOC Level 1 — Cyber Defence Frameworks

Frameworks that describe how attacks unfold and how to defend against them: the Pyramid of Pain, Cyber Kill Chain, Unified Kill Chain and MITRE, followed by two practical challenges that apply them.

**Rooms:** Pyramid of Pain · Cyber Kill Chain · Unified Kill Chain · MITRE · Summit · Eviction

> This file covers **Eviction**, the module's final challenge. The other rooms are in `Cyber Defence Frameworks Notes.txt`.

**Skills covered:** MITRE ATT&CK Navigator · threat-group profiling · mapping TTPs to detections

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
