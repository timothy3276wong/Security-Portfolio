# TryHackMe SOC Level 1 — Capstone Challenges

The final module: four full investigations with no guidance. Each starts from a single artefact (a phishing email, a log set, a memory dump) and asks you to reconstruct the **entire attack chain**. Together they use nearly every tool from the path: email analysis, PowerShell logs, Sysmon, PCAPs, memory forensics and the SIEM.

**Rooms:** Tempest · Boogeyman 1 · Boogeyman 2 · Boogeyman 3

**Skills covered:** EVTX → CSV timelining · Sysmon process-tree reconstruction · PCAP correlation · decoding encoded PowerShell · LNK and macro analysis · PowerShell script block logs with `jq` · DNS exfil detection · memory forensics with Volatility · Kibana hunting across multiple hosts · mapping an intrusion to ATT&CK

> These notes cover the **method and attack patterns**. The flag answers are deliberately left out.

---

## Tempest

**Scenario:** a Windows workstation was compromised through a **malicious Word document**. You get Sysmon logs, Windows event logs and a PCAP, and have to rebuild the intrusion by correlating endpoint and network evidence.

### Tooling
| Tool | Use |
|---|---|
| **EvtxECmd** | Convert `.evtx` → CSV/JSON for bulk analysis |
| **Timeline Explorer** | Filter/sort that CSV like a spreadsheet (column filters, grouping) |
| **SysmonView** | Visualize Sysmon events grouped by process and image |
| Event Viewer | Quick filtering by Event ID |
| **Wireshark** / **Brim** | Packet detail / fast Zeek-style summaries of the PCAP |
| `Get-FileHash` | Check that the artefacts are intact before you start |

### Attack chain
| Stage | What happened | Evidence |
|---|---|---|
| Initial access | User downloads and opens a doc. **Word spawns unexpected children** (a known Office remote-code-execution technique worth researching) | Sysmon 1: `WINWORD.EXE` → `msdt.exe` / shell |
| Execution | **Base64-encoded PowerShell** downloads and runs the next stage | Sysmon 1 command line → decode it |
| Persistence | Payload dropped in the user's **Startup folder** | Sysmon 11 |
| C2 | Implant **beacons over HTTP**, with commands and output **encoded in requests and responses** | Sysmon 3/22 + HTTP in the PCAP |
| Discovery & pivot | Host enumeration, credential harvesting, a **reverse SOCKS proxy** to reach internal services, remote management login with stolen creds | Sysmon 1, network connections |
| Privilege escalation | Low-privilege service account **abuses a token privilege** to reach SYSTEM, then a second C2 binary runs | Sysmon 1 (parent/user change) |
| Actions & persistence | New local users, one added to Administrators, plus a **new service** | 4720, 4732, 7045 / Sysmon 1 (`sc`, `net`) |

**Method:** find the first malicious process → follow `ProcessGuid` / `ParentProcessGuid` forward → for every network event, pivot into the PCAP at that timestamp → decode anything encoded.

---

## Boogeyman 1

**Scenario:** a new threat group targets a logistics company. A finance employee received an "invoice" email. You get the **.eml**, **PowerShell script block logs (JSON)** and a **PCAP**.

### Tooling
`Thunderbird` (open the email, extract the attachment) · `base64` + archive tools · **`lnkparse`** (read a shortcut's hidden command line) · **`jq`** (query the JSON logs) · Wireshark/tshark · grep/sed/awk

```bash
# Script block text, in time order
jq -s 'sort_by(.Timestamp) | .[].ScriptBlockText' powershell.json
```

### Attack chain
1. **Phishing:** spoofed invoice reminder sent through a third-party mail relay, carrying a **password-protected archive** (scanners can't open it, so it slips past the filter)
2. **Execution:** the archive holds an **LNK** whose arguments run `powershell -nop -w hidden -enc ...`, which downloads and runs a remote script
3. **C2:** the script **polls the attacker's server over HTTP**, using a custom header as a simple authentication token, and POSTs command output back
4. **Discovery:** `whoami`, directory and process listings, then an open-source **enumeration tool** is downloaded
5. **Collection:** reads a **note-taking app's SQLite database** and finds a sensitive password database file
6. **Exfiltration:** the file is **hex-encoded and sent in DNS queries**, in chunks, as subdomains of an attacker domain

**Detection angles:** email headers (relay, authentication results), `-enc` + hidden-window PowerShell, beaconing with an odd header, and DNS queries with long hex subdomains:
```
dns.qry.name matches "^[0-9a-f]{20,}\."     # Wireshark
```

---

## Boogeyman 2

**Scenario:** the same group comes back with new TTPs against a **Human Resources** specialist, using a malicious "resume" attachment. You get the **phishing email** and a **memory dump** of the workstation. There are no logs this time, so **memory forensics** is the only evidence.

### Tooling
- **olevba** (oletools): extract and analyze the document's VBA macro
  ```bash
  olevba resume.doc
  ```
- **Volatility 3:**
  ```bash
  vol -f mem.raw windows.pstree       # parent → child tree
  vol -f mem.raw windows.psscan       # includes hidden/terminated processes
  vol -f mem.raw windows.cmdline      # command lines per process
  vol -f mem.raw windows.netscan      # connections + owning PID
  vol -f mem.raw windows.filescan     # file objects still in memory
  ```
- `strings mem.raw | grep -i schtasks`: find persistence commands in raw memory

### Attack chain
1. **Initial access:** resume-themed Word doc
2. **Macro execution:** the VBA downloads a second-stage **script**, which runs via a Windows **script host** (`wscript`/`cscript`)
3. **Stage 2:** the script downloads a standalone **binary** and runs it from a **non-standard path**
4. **C2:** that binary opens an outbound connection (visible in `netscan` with its PID)
5. **Persistence:** a **scheduled task** runs a hidden PowerShell command that **reads encoded content from the registry** and executes it (fileless: the payload never sits on disk as a file)

**Lesson:** memory holds what disk and logs don't: running processes, command lines, network sockets, and decoded payloads. The **process tree** (`WINWORD → wscript → binary`) tells the story just as Sysmon would.

---

## Boogeyman 3

**Scenario:** the group's biggest operation. The **CEO** opens an attachment from a phishing email, and it spreads to the whole domain. All evidence is in **Kibana** (mainly Sysmon from several hosts), and the incident window is about two days.

### Method in Kibana
- **Set the time range** to the incident window first
- Filter by `host.name` and `event.code` (Sysmon 1 = process, 3 = network, 11 = file)
- Pivot on anything unique: a filename, hash, IP or `process.parent.name` → search for it across **all** hosts to see where else it appears
```
host.name : "WKSTN-CEO" and event.code : 1 and process.parent.name : "explorer.exe"
process.command_line : *rundll32* or process.command_line : *schtasks*
```

### Attack chain
| Stage | What happened |
|---|---|
| Initial access | A document-looking payload delivered **inside an ISO image** (opening an ISO mounts it, and files inside can avoid the Mark-of-the-Web warning) |
| Execution | Built-in utilities copy a file to a **temp folder**. It's actually a **DLL**, run through a **trusted system binary** (LOLBin) |
| Persistence | **Scheduled task** that reruns the DLL |
| C2 | Outbound connections from the implant to attacker infrastructure |
| Privilege escalation | User is a local admin, so a **UAC bypass** through a trusted, auto-elevating Windows binary |
| Discovery | Users, groups and shares enumerated, including with a well-known **PowerShell AD recon script** |
| Credential access | A well-known **credential-dumping tool** is downloaded and run against LSASS |
| Lateral movement | **Pass-the-hash** with the dumped hashes to run commands on another workstation and then the **domain controller** |
| Domain compromise | **DCSync**: abusing directory replication rights to pull every account's password hash from the DC |
| Impact | Downloading and staging **ransomware** |

**Lesson:** one phishing click becomes a whole-domain compromise in a few hours. Each pivot (workstation → workstation → DC) shows up as a **logon or process event on a new host**, which is why you search indicators **across all hosts**, not only the first one.

---

## Patterns across all four

| Theme | Seen in |
|---|---|
| Phishing with an attachment designed to dodge scanners (passworded ZIP, ISO, macro doc) | All four |
| **Encoded PowerShell** (`-enc`, hidden window) | Tempest, B1, B2 |
| LOLBins / trusted binaries for execution | Tempest, B3 |
| HTTP beaconing C2 | All four |
| Scheduled task / Startup / service persistence | All four |
| Data hidden in DNS or the registry | B1 (DNS exfil), B2 (registry payload) |
| Credential theft → lateral movement | Tempest, B3 |

**The universal method:** find patient zero → rebuild the **process tree** → decode every encoded blob → pivot every IP/domain/hash into the other data sources → map each step to an **ATT&CK tactic** → write it up with the 5 Ws.
