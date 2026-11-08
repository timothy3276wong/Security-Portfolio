# TryHackMe SOC Level 1 — Network Security Monitoring

The previous module was about reading packets. This one is about **detecting attacks in network data**. You find recon, MITM and exfiltration in perimeter logs and traffic, then automate the detection with an IDS (Snort).

**Rooms:** Network Security Essentials · Network Discovery Detection · Data Exfiltration Detection · Man-in-the-Middle Detection · IDS Fundamentals · Snort

**Skills covered:** perimeter controls & logs · attack-chain reconstruction from logs · horizontal vs. vertical scans · internal vs. external recon · exfil over DNS/FTP/HTTP/ICMP · ARP/DNS spoofing & SSL stripping · IDS types & detection methods · Snort modes, rules and PCAP analysis

---

## Network Security Essentials

A network is a single ecosystem of servers, workstations, apps and security devices, so a compromise in one part spreads to the others. Defence starts with **visibility**: knowing what assets exist and what traffic is normal.

### The perimeter
The boundary between the internal network and the outside world. Controls there:
| Control | What its logs show |
|---|---|
| **Firewall** | Allowed/blocked connections (src, dst, port, action, bytes) |
| **IDS/IPS** | Signature matches, e.g. known exploits, C2 beacons |
| **WAF** | Blocked web attacks (SQLi, XSS) and the source IP |
| **VPN / remote access** | Authentication successes and failures, assigned internal IP |

### Reconstructing a breach from perimeter logs
Each stage of the attack leaves a trace in a different log source:

| Stage | Indicator | Log source |
|---|---|---|
| Recon | One external IP blocked on many ports | Firewall |
| Brute force | Many failed VPN logins → **then one success** | VPN auth |
| Initial access | Successful session + assigned internal IP | VPN |
| Lateral movement | Compromised host → other internal hosts on **445 (SMB) / 3389 (RDP) / 22 (SSH)** | Firewall (internal) |
| C2 | Regular callbacks from an internal host to one external IP | IDS |
| Exfiltration | Large outbound byte count to an external destination | Firewall |

**Method:** filter by keyword → extract fields → sort and count (top source IPs, top targeted ports) → **pivot the suspicious IP** across every log source → build a timeline.
```bash
grep "BLOCK" firewall.log | awk '{print $5}' | sort | uniq -c | sort -nr | head
#  4812 203.0.113.50    ← loudest scanner
```

---

## Network Discovery Detection

**Network discovery** = mapping hosts, open ports and services. Attackers use it to find a way in. Defenders use it for asset inventory, closing unneeded ports and patching. The same scan can come from either side, which is why context matters.

### External vs. internal scanning
| | External | Internal |
|---|---|---|
| Source | Internet → your public IPs | Inside host → other inside hosts |
| ATT&CK tactic | **Reconnaissance** | **Discovery** |
| Means | Constant background noise | **Someone already has a foothold** |
| Severity | Low | **High** |

### Horizontal vs. vertical scanning
```
Horizontal: ONE port, MANY hosts       Vertical: MANY ports, ONE host
10.0.0.1:445                            10.0.0.5:21
10.0.0.2:445                            10.0.0.5:22
10.0.0.3:445   → "who runs SMB?"        10.0.0.5:80    → "what does this box run?"
...                                     ...
```
Horizontal is what worms do (WannaCry sweeping **445**). Vertical profiles a specific target.

### Scan mechanics & how they look
| Technique | Traffic | Detection notes |
|---|---|---|
| **Ping sweep** | ICMP echo to every host in a range | Burst of ICMP from one source |
| **TCP SYN scan** | SYN → SYN/ACK → RST, handshake never finishes | Lots of half-open connections. In Zeek `conn_state`, `S0` (no reply) and `REJ` (rejected) pile up |
| **UDP scan** | UDP probes, closed ports return ICMP port unreachable | Slow, unreliable, timeout-based |

**Separating benign from malicious:** allowlist known vulnerability scanners and document authorized internal scans so they're excluded from rules. Enrich unknown sources with threat intel, and raise severity for internal sources.

---

## Data Exfiltration Detection

**Exfiltration** = unauthorized transfer of data out of the organization. It's usually the attacker's end goal (ATT&CK **TA0010**), and the SOC's last chance to stop the damage.

**General indicators:** outbound volume much bigger than usual for a host, transfers at odd hours, connections to new or rare destinations, data going out over a protocol that normally carries little, and **upload > download** ratios that are unusual for that host.

### Channels
| Channel | How it works | What to look for |
|---|---|---|
| **DNS tunnelling** | Data encoded into subdomains: `<base64chunk>.exfil.evil.com` | Long query names, high-entropy labels, huge query counts to one domain, unusual TXT/NULL records |
| **FTP** | Plain upload with `STOR` | `STOR` of sensitive filenames, large transfers to external FTP servers |
| **HTTP(S)** | POST bodies or uploads to attacker web servers / cloud storage | Large `POST`s, uploads to paste/file-share sites, odd user agents |
| **ICMP** | Data stuffed into echo request payloads | Payloads larger than the normal 32–64 bytes, steady ping streams to one external IP |

**Detection examples:**
```
# Wireshark
dns.qry.name.len > 50 and !mdns
ftp.request.command == "STOR"
http.request.method == "POST" and frame.len > 1000
icmp and data.len > 64
```
```spl
# Splunk: top talkers by bytes out
index=network sourcetype=firewall direction=outbound
| stats sum(bytes_out) as total by src_ip, dest_ip
| sort -total
```
**Why exfil tunnels through DNS and ICMP:** firewalls almost always allow them outbound. This is also why the room correlates traffic with endpoint and SIEM data instead of relying on one source.

---

## Man-in-the-Middle Detection

A **MITM** attacker places themselves between two endpoints to intercept, modify or redirect traffic. Detection combines network monitoring, certificate validation and behavioural analysis.

### ARP spoofing
The attacker sends forged ARP replies so victims map the gateway's IP to the attacker's MAC (ARP has no authentication).
- **Indicators:** one IP claiming two MACs, a burst of unsolicited (gratuitous) ARP replies, and the gateway's MAC suddenly changing
```
arp.duplicate-address-detected
arp.opcode == 2                              # replies; look for ones nobody asked for
```
**Mitigation:** Dynamic ARP Inspection on switches, static ARP entries for critical hosts.

### DNS spoofing
Forged DNS responses send victims to an attacker-controlled IP.
- **Indicators:** responses from a host that isn't your DNS server, **two different answers for the same query**, answers pointing popular domains at internal or unusual IPs, abnormally low TTLs
```
dns.flags.response == 1 and !(ip.src == <legit DNS server>)
```
**Mitigation:** DNSSEC, and forcing all clients to use internal resolvers.

### SSL stripping
The attacker downgrades the victim's HTTPS connection to HTTP. The victim talks HTTP to the attacker, and the attacker talks HTTPS to the real site.
- **Indicators:** logins to sites that should always be HTTPS showing up as **cleartext HTTP POSTs**, missing TLS handshakes where they'd be expected, redirects that go from HTTPS to HTTP
```
http.request.method == "POST" and http.host contains "bank"
```
**Mitigation:** **HSTS** (the browser refuses HTTP for that domain) and HSTS preload lists.

**Common thread:** all three abuse protocols that **trust whatever answers first** (ARP, DNS) or that let the client fall back to something weaker (HTTP). Detection means looking for answers that conflict with what's known to be legitimate.

---

## IDS Fundamentals

An **IDS (Intrusion Detection System)** watches for malicious activity that gets past perimeter controls and **alerts**. An **IPS** sits inline and can also **block**.

### Types
| By deployment | |
|---|---|
| **HIDS** | On a single host (logs, file integrity, processes) |
| **NIDS** | On a network segment (via a TAP or SPAN port) |

| By detection method | Strength | Weakness |
|---|---|---|
| **Signature-based** | Accurate on known attacks, few false positives | Blind to zero-days and variants |
| **Anomaly-based** | Can catch unknown attacks | Needs a baseline, more false positives |
| **Hybrid** | Mix of both | More complex |

Snort is the room's example: open-source and signature-based (with some anomaly capability). It has three modes: **sniffer**, **packet logger** and **NIDS**.

---

## Snort

### Modes & key flags
| Mode | Command | Notes |
|---|---|---|
| **Sniffer** | `snort -v` | Prints headers. `-d` payload, `-e` link-layer headers, `-X` full hex dump |
| **Packet logger** | `snort -dev -l ./logs` | Writes to a log directory (tcpdump format). `-K ASCII` for readable logs |
| **Read logs / PCAP** | `snort -r snort.log.1234` | Add BPF filters: `snort -r file 'tcp port 80'`, `-n 10` for the first 10 packets |
| **NIDS** | `snort -c /etc/snort/snort.conf -A console` | Apply rules and alert |
| **IPS (inline)** | `snort -c snort.conf -q -Q --daq afpacket -i eth0:eth1 -A console` | `drop` rules actually block |
| **Test config** | `snort -c snort.conf -T` | Validates config and rules |

**Alert modes (`-A`):** `console` (fast-style output to screen) · `cmg` (header + hex payload) · `fast` (one line to the alert file) · `full` (full alert to file) · `none`. Other useful flags: `-q` quiet, `-D` run as daemon.

**PCAP investigation:**
```bash
snort -c local.rules -r capture.pcap -A console -l .     # alerts on a single pcap
snort -c local.rules --pcap-list="a.pcap b.pcap" -A console --pcap-show
```

### Rule structure
```
action  proto  src_ip  src_port  ->  dst_ip  dst_port  (options)
alert   tcp    any     any       ->  any     21        (msg:"FTP connection"; sid:1000001; rev:1;)
```
| Header part | Values |
|---|---|
| Action | `alert` · `log` · `drop` (block + log, IPS) · `reject` (block + RST) |
| Protocol | `tcp` `udp` `icmp` `ip` |
| Addresses / ports | `any`, `192.168.1.0/24`, `!10.0.0.5`, `[21,23]`, `1:1024` (range) |
| Direction | `->` one way · `<>` both ways |

**Rule options:**
| Type | Options |
|---|---|
| General | `msg` (alert text) · **`sid`** (rule ID: <100 reserved, 100–999,999 official rules, **≥1,000,000 your own**) · `rev` (revision) · `reference` (CVE etc.) |
| Payload | `content:"string"` or `content:"\|0D 0A\|"` (hex) · `nocase` · `fast_pattern` |
| Non-payload | `flags:S` (TCP flags) · `dsize:>100` (payload size) · `id` (IP ID) · `sameip` · `ttl` |

**Worked examples:**
```
# Any ICMP (ping) on the network
alert icmp any any <> any any (msg:"ICMP detected"; sid:1000001; rev:1;)

# Nmap-style SYN to SSH
alert tcp any any -> $HOME_NET 22 (msg:"SYN to SSH"; flags:S; sid:1000002; rev:1;)

# Cleartext FTP login attempt as admin
alert tcp any any -> any 21 (msg:"FTP admin login"; content:"USER admin"; nocase; sid:1000003; rev:1;)

# Possible ICMP tunnel: unusually large ping payload
alert icmp any any -> any any (msg:"Large ICMP payload"; dsize:>64; sid:1000004; rev:1;)
```

**Config:** `/etc/snort/snort.conf` sets `HOME_NET` / `EXTERNAL_NET`, the DAQ, output plugins and which rule files load. Custom rules go in `/etc/snort/rules/local.rules`.

**Takeaway:** Snort turns the manual Wireshark hunting from the previous module into **repeatable detections**. Everything this module covers (scans, tunnels, exfil, cleartext logins) can be written as a rule.
