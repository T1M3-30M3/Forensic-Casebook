# Web Investigation PCAP Analysis Cheat Sheet

## 🔍 Quick Overview
```bash
tcpdump -r WebInvestigation.pcap
```

## 📊 Top Talkers
```bash
tshark -r WebInvestigation.pcap -q -z conv,ip
```

## 📈 Protocol Breakdown
```bash
tshark -r WebInvestigation.pcap -q -z io,phs
```

## 🔎 Filter Suspicious Traffic
```bash
# HTTP Requests
tshark -r WebInvestigation.pcap -Y "http.request"

# DNS Queries
tshark -r WebInvestigation.pcap -Y "dns"

# MySQL Traffic
tshark -r WebInvestigation.pcap -Y "mysql"
```

## 💉 Detect SQL Injection Attempts
```bash
strings WebInvestigation.pcap | grep -i "select"
strings WebInvestigation.pcap | grep -i "union"
strings WebInvestigation.pcap | grep -i "or 1=1"
strings WebInvestigation.pcap | grep -i "information_schema"
```

## 🔗 Follow TCP Streams
```bash
tshark -r WebInvestigation.pcap -q -z follow,tcp,ascii,0
```

## 📤 Detect Data Exfiltration
```bash
tshark -r WebInvestigation.pcap -z io,stat,1
tcpdump -r WebInvestigation.pcap src net 192.168.0.0/16
```

## 🕵️ Suspicious User Agents
```bash
tshark -r WebInvestigation.pcap -Y "http.user_agent"
```

## 🌐 Extract IPs for Threat Intel
```bash
tshark -r WebInvestigation.pcap -T fields -e ip.src -e ip.dst | sort | uniq
```

## ⚠️ Quick Indicators
```bash
strings WebInvestigation.pcap | grep -i "password"
strings WebInvestigation.pcap | grep -E "[A-Za-z0-9+/=]{20,}"
```

## ⏱️ Timeline Analysis
```bash
tshark -r WebInvestigation.pcap -T fields -e frame.time
```

## 💾 Reassemble HTTP Objects
```bash
tshark -r WebInvestigation.pcap --export-objects http,./http_objects
```

## 🔄 Detect Retransmissions & Anomalies
```bash
tshark -r WebInvestigation.pcap -Y "tcp.analysis.retransmission"
tshark -r WebInvestigation.pcap -Y "tcp.analysis.flags"
```

## 🌐 Long-Lived Connections (C2/DB Abuse)
```bash
tshark -r WebInvestigation.pcap -q -z conv,tcp
```

## 📤 Extract HTTP POST Data
```bash
tshark -r WebInvestigation.pcap -Y "http.request.method == POST" -T fields -e http.file_data
```

## 🔐 Encoded/Obfuscated Payloads
```bash
tshark -r WebInvestigation.pcap -Y "data.data"
echo "<hex_data>" | xxd -r -p
```

## 🧬 Suspicious Domains (DNS)
```bash
tshark -r WebInvestigation.pcap -T fields -e dns.qry.name | sort | uniq -c | sort -nr
```

## 📡 Detect Beaconing
```bash
tshark -r WebInvestigation.pcap -T fields -e frame.time_epoch -e ip.src -e ip.dst
```

## 📏 Filter by Packet Size
```bash
# Large packets (exfil)
tshark -r WebInvestigation.pcap -Y "frame.len > 1000"

# Small stealth exfil
tshark -r WebInvestigation.pcap -Y "frame.len < 100"
```

## 🔍 Port Scanning
```bash
tshark -r WebInvestigation.pcap -T fields -e ip.src -e tcp.dstport | sort | uniq -c | sort -nr
```

## 🔒 TLS Handshake (SNI Extraction)
```bash
tshark -r WebInvestigation.pcap -Y "ssl.handshake.type == 1" -T fields -e ip.dst -e ssl.handshake.extensions_server_name
```

## 👤 Reconstruct Credentials
```bash
tshark -r WebInvestigation.pcap -Y "ftp.request.command == USER"
tshark -r WebInvestigation.pcap -Y "ftp.request.command == PASS"
```

## 📊 Flow-Based Analysis
```bash
tshark -r WebInvestigation.pcap -T fields -e ip.src -e ip.dst -e frame.len | \
awk '{bytes[$1]+=$3} END {for (ip in bytes) print ip, bytes[ip]}'
```

## 🚨 Suspicious TCP Flags
```bash
# SYN Scans
tshark -r WebInvestigation.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0"

# FIN Scans
tshark -r WebInvestigation.pcap -Y "tcp.flags.fin==1 && tcp.flags.ack==0"
```

## 📄 Carve File Types
```bash
strings WebInvestigation.pcap | grep -i "pdf"
strings WebInvestigation.pcap | grep -i "zip"
```

## 🔄 Lateral Movement
```bash
tshark -r WebInvestigation.pcap -Y "ip.src==192.168.0.0/16 && ip.dst==192.168.0.0/16"
```

## 🍪 User Sessions (Cookies)
```bash
tshark -r WebInvestigation.pcap -Y "http.cookie"
```

## 💻 Command Execution
```bash
strings WebInvestigation.pcap | grep -E "cmd=|exec=|/bin/sh|powershell"
```

## 📊 HTTP Status Codes
```bash
tshark -r WebInvestigation.pcap -T fields -e http.response.code | sort | uniq -c
```

---

# 🎯 KEY INVESTIGATION FINDINGS

## 🕵️ Attacker IP
```bash
http.request
frame contains "SELECT" || frame contains "UNION"
ip.addr == X.X.X.X
```
```bash
111.224.250.131
```

## 🌍 Geographical Origin
```bash
Use WHOIS lookup
```

## 🐛 Vulnerable PHP Script
```bash
search.php
```

## 💉 First SQLi Attempt URI
```bash
ip.src == 111.224.250.131 && http.request.method == GET
```
```bash
/search.php?search=book and 1=1; -- -
```

## 🗄️ Database Enumeration URI
```bash
tshark -r WebInvestigation.pcap -Y "http.request" -T fields -e http.request.full_uri
tshark -r WebInvestigation.pcap -Y 'http.request.uri contains "information_schema"' -T fields -e http.request.full_uri
tshark -r WebInvestigation.pcap -Y 'http.request.uri contains "SELECT"' -T fields -e http.request.full_uri
tshark -r WebInvestigation.pcap -Y 'http.request.uri contains "%73%65%6C%65%63%74"' -T fields -e http.request.full_uri
tshark -r WebInvestigation.pcap -Y 'http.request && frame contains "search.php" && frame contains "INFORMATION_SCHEMA"' -T fields -e http.request.full_uri
```
```bash
Filter: `http.request.uri contains "information_schema"`
ip.dst==111.224.250.131 and ip.src==73.124.22.98 and http.response.code == 200
ip.dst == 111.224.250.131 and http.response.code == 200
```

## 👥 Users Table
```bash
customers
```

## 🗂️ Hidden Directory
```bash
tshark -r WebInvestigation.pcap -Y "http.request && frame contains \"search.php\"" -T fields -e http.request.uri
tshark -r WebInvestigation.pcap -Y "http.request.uri matches \"/.*/\"" -T fields -e http.request.uri

tshark -r WebInvestigation.pcap -Y "http.request && !(frame contains \"search.php\")" -T fields -e http.request.uri | sort | uniq -c | sort -nr
```
```bash
/admin/
```

## 🔐 Compromised Credentials
```bash
tshark -r WebInvestigation.pcap -Y "http.request.method == POST" -T fields -e http.file_data | while read line; do echo $line | xxd -r -p; echo; done

tshark -r WebInvestigation.pcap -Y 'http.request.method == POST && frame contains "login"' -T fields -e http.file_data | while read line; do echo $line | xxd -r -p; echo; done

http.request.method == POST
```
```bash
admin:admin123!
```

## 🐙 Malicious Upload
```bash
NVri2vhp.php
```

---

## 🔍 Advanced Filters

```bash
# Attacker-specific traffic
tshark -r WebInvestigation.pcap -Y "ip.addr == 111.224.250.131"

# SQLi patterns
tshark -r WebInvestigation.pcap -Y 'frame contains "SELECT" || frame contains "UNION"'

# POST login attempts
tshark -r WebInvestigation.pcap -Y 'http.request.method == POST && frame contains "login"'

# Admin directory access
tshark -r WebInvestigation.pcap -Y 'http.request.uri contains "/admin/"'
```

Pro Tip: Pipe output to `grep`, `sort`, `uniq -c` for better analysis! 🚀
