# Security Portfolio

Hi, I'm **Timothy Wong**, a Computer Engineering student at Queen's University working toward a career in security operations (SOC). This repo documents my hands-on cybersecurity learning: write-ups, lab notes, and what I took away from each exercise.

[LinkedIn](https://www.linkedin.com/in/timothy-wong-13891a340/) · timothy.wong@queensu.ca

---

## Contents

| Folder | What it covers | Status |
| --- | --- | --- |
| [`OverTheWire Bandit`](./OverTheWire%20Bandit) | Linux security wargame write-ups, levels 0–32 | Completed |
| `Homelab` | Isolated virtual lab for practicing network scanning and detection | In progress |
| `TryHackMe SOC Level 1` | Notes from the SOC analyst learning path | In progress |

---

## OverTheWire Bandit

[Bandit](https://overthewire.org/wargames/bandit/) is a beginner Linux wargame where each level hides the password to the next behind a security concept. I completed all levels from 0 to 32.

**Skills practiced**
- **Linux command line:** file discovery, permissions, text processing (`find`, `grep`, `sort`, `uniq`, `strings`, `base64`, `tr`, `xxd`)
- **Networking:** SSH key authentication, port scanning with `nmap`, connecting to services with `netcat` and `openssl s_client`
- **Privilege and misconfiguration abuse:** setuid binaries, scheduled `cron` jobs, restricted-shell escapes
- **Scripting:** Bash scripts to automate brute-force and enumeration tasks
- **Git:** digging through commit history, branches, and tags for leaked secrets

**Write-up format**

Each level's write-up follows the same structure:
1. **Goal:** what the level asks for
2. **Concept:** the security idea behind it
3. **Approach:** the commands I used and why they work
4. **Takeaway:** what this teaches about real-world systems

> In line with OverTheWire's rules, these write-ups explain the method but do **not** include level passwords.

---

## Certifications & Training

- **ISC2 Certified in Cybersecurity (CC):** security principles, access control, network security, security operations, incident response
- **TryHackMe SOC Level 1:** in progress

---

## Tools & Skills

`Linux` · `Bash` · `SSH` · `Nmap` · `netcat` · `Git` · `Python` · `C`

---

## Disclaimer

Everything in this repository was done in legal, purpose-built training environments (wargames, CTF platforms, and my own isolated lab). Nothing here is intended for use against systems I don't own or have permission to test.
