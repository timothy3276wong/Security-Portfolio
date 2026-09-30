# OverTheWire: Bandit — Walkthrough Notes

[Bandit](https://overthewire.org/wargames/bandit/) is a beginner wargame that teaches the Linux command line through a series of levels. Each level hides a password that unlocks the next, and reaching it forces you to learn a specific tool or concept — file handling, text processing, encoding, networking, privilege escalation, and Git.

These are my technique notes from working through the game. **Passwords are intentionally omitted** (OverTheWire asks players not to publish them, and the password is the throwaway part anyway) — what matters is the method, which is what carries over into real work.

**Skills covered:** SSH · file manipulation · `find` · `grep` / `sort` / `uniq` / `strings` · base64 & ROT13 decoding · compression formats · `nc` / `openssl` / port scanning · setuid binaries · cron jobs · brute forcing · shell escapes · Git.

---

## Getting connected

### Level 0 — SSH access
Connect to the game server over SSH on a non-standard port.
```bash
ssh -p 2220 bandit0@bandit.labs.overthewire.org
```

---

## Working with files

### Level 0 → 1 — Reading a file
The password sits in a plain file in the home directory. Read it with `cat`.
```bash
cat readme
```

### Level 1 → 2 — Awkwardly named files (`-`)
The file is named `-`, which most commands read as "stdin" or an option flag. Prefix it with a path to force it to be treated as a filename.
```bash
cat ./-
```

### Level 2 → 3 — Filenames with spaces
Quote the name (or escape the spaces, or use tab-completion) so the shell treats it as one argument.
```bash
cat "./spaces in this filename"
```

### Level 3 → 4 — Hidden files
The file is hidden (its name starts with a dot). Reveal dotfiles with `ls -a`.
```bash
ls -a
```

### Level 4 → 5 — Identifying the readable file
One of several files is human-readable; the rest are binary. Use `file` to check their types and find the ASCII text one.
```bash
file ./*
```

### Level 5 → 6 — `find` by file properties
The password file is nested somewhere in a directory tree and is identifiable by size, readability, and being non-executable. Let `find` filter on those properties.
```bash
find . -type f -size 1033c -readable ! -executable
```

### Level 6 → 7 — `find` across the whole filesystem
This time the file is anywhere on the system, but owned by a specific user/group and of a known size. Search from `/` and discard permission-denied noise.
```bash
find / -user bandit7 -group bandit6 -size 33c 2>/dev/null
```

---

## Filtering and searching text

### Level 7 → 8 — `grep` for a keyword
The password is on the line next to a known word inside a large file.
```bash
grep millionth data.txt
```

### Level 8 → 9 — `sort` + `uniq`
The password is the only line that appears exactly once. `uniq` only collapses *adjacent* duplicates, so sort first.
```bash
sort data.txt | uniq -u
```

### Level 9 → 10 — `strings` on a binary
The password is one of the few human-readable strings in a binary file, marked by several `=` characters. Extract printable strings, then filter.
```bash
strings data.txt | grep '==='
```

---

## Encoding and decoding

### Level 10 → 11 — Base64
The file contents are base64-encoded.
```bash
base64 -d data.txt
```

### Level 11 → 12 — ROT13
A rotation cipher shifts each letter 13 places. `tr` can remap the alphabet in one pass.
```bash
cat data.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

### Level 12 → 13 — Nested compression
The file is a hexdump of repeatedly compressed data. Reverse the hexdump, then unpack layer by layer — using `file` at each step to see what format you're dealing with (gzip, bzip2, tar) and renaming to the right extension before decompressing.
```bash
xxd -r data.txt > data.bin
file data.bin            # repeat: identify → rename → decompress
```

---

## SSH keys and network services

### Level 13 → 14 — Key-based SSH login
No password this time — you're given an RSA private key. Authenticate with `-i`.
```bash
ssh -i bandit14.key -p 2220 bandit14@bandit.labs.overthewire.org
```

### Level 14 → 15 — Sending data to a port with `netcat`
Submit the current level's password to a service listening on localhost.
```bash
nc localhost 30000
```

### Level 15 → 16 — TLS-encrypted service
The service expects an encrypted connection. `openssl s_client` is netcat-with-TLS.
```bash
openssl s_client -connect localhost:30001
```

### Level 16 → 17 — Port scanning + TLS
Scan a port range to find which are open, test which speak SSL/TLS, submit the password to the right one, and receive a private key in return. Save that key and use it to SSH in.
```bash
nmap -p 31000-32000 localhost          # find open ports
openssl s_client -connect localhost:<port>
```

---

## Comparing files and remote execution

### Level 17 → 18 — `diff`
Two nearly identical files differ on one line — the password.
```bash
diff passwords.old passwords.new
```

### Level 18 → 19 — Non-interactive SSH
`.bashrc` logs you out immediately on an interactive login, so run your command as part of the SSH invocation instead of getting a shell.
```bash
ssh -p 2220 bandit18@bandit.labs.overthewire.org 'cat readme'
```

---

## Privilege escalation — setuid binaries

### Level 19 → 20 — Running a command as another user
A setuid binary executes commands as the next user. Use it to read that user's password file.
```bash
./bandit20-do cat /etc/bandit_pass/bandit20
```

### Level 20 → 21 — setuid + a self-hosted listener
A setuid binary connects to a port and echoes back the *next* password if it first receives the *current* one. Stand up a listener that serves the current password, then point the binary at it.
```bash
# terminal 1: listener that sends the current password
echo '<current_password>' | nc -l -p 1337
# terminal 2:
./suconnect 1337
```

### Level 26 → 27 — setuid again
Same idea as level 19 — a setuid helper reads the next password file for you.
```bash
./bandit27-do cat /etc/bandit_pass/bandit27
```

---

## Privilege escalation — cron jobs

### Level 21 → 22 — Reading a scheduled job
A cron job runs on a schedule as a higher-privileged user. Read the cron config in `/etc/cron.d/`, follow it to the script it runs, and read the file that script drops into `/tmp`.
```bash
cat /etc/cron.d/*
```

### Level 22 → 23 — Reproducing a job's logic
The cron script derives an output filename (e.g. from a hash of a username) and writes the password there. Read the script, recompute the filename yourself, and read it.

### Level 23 → 24 — Getting cron to run *your* script
A cron job runs, as the target user, any script placed in a watched directory. Drop in a script that copies the password to a world-readable location.
```bash
#!/bin/bash
cat /etc/bandit_pass/bandit24 > /tmp/mypassword
```

---

## Brute forcing

### Level 24 → 25 — Brute-forcing a PIN over netcat
A service wants the current password plus an unknown 4-digit PIN. Loop through all 10,000 combinations and pipe them in at once.
```bash
for i in $(seq -w 0 9999); do
    echo "<bandit24_password> $i"
done | nc localhost 30002
```

---

## Shell escapes

### Level 25 → 26 — Escaping a pager into an editor into a shell
The login shell is `more` (a pager) instead of bash. Shrink the terminal window so the text is forced to page, open the editor from the pager with `v`, then spawn a shell from within `vi`.
```
:set shell=/bin/bash
:shell
```

### Level 32 → 33 — Escaping an uppercase shell
Everything you type is converted to uppercase, so normal commands fail — but `$0` (the name of the current shell) still expands to a usable shell.
```bash
$0
```

---

## Git

### Level 27 → 28 — Cloning a repo
The password lives in a Git repository. Clone it over SSH and read the file.
```bash
git clone ssh://bandit27-git@localhost:2220/home/bandit27-git/repo
```

### Level 28 → 29 — Digging through history
The current file has the password redacted, but an earlier commit didn't. Inspect the log and show the old commit.
```bash
git log
git show <commit>
```

### Level 29 → 30 — Other branches
The password isn't on `master` — check the other branches.
```bash
git branch -a
git checkout dev
```

### Level 30 → 31 — Tags
The password is stored in a Git tag rather than a commit.
```bash
git tag
git show <tag>
```

### Level 31 → 32 — Pushing to the remote
Follow the repo's README: create the required file, get past `.gitignore`, commit, and push. The server responds to the push.
```bash
git add -f key.txt
git commit -m "add key"
git push
```

---

## Finished

Level 33 is the end of the current game, there's no further level to unlock. Working through Bandit end-to-end builds the command-line fluency that everything else in security (enumeration, privilege escalation, log analysis) is built on top of.
