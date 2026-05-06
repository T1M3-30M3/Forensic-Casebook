# NukeTheBrowser.pcap Analysis

## 1. Highest Targeted IP Address
```bash
tshark -r NukeTheBrowser.pcap -T fields -e ip.dst | sort | uniq -c | sort -nr | head -1
```
**Answer**: [IP from command output]

## 2. Attack Protocol
**Path**: Statistics → Protocol Hierarchy  
**Answer**: `http`

## 3. Malicious Executable URL (no parameters)
**Filter**: `frame contains "filename="`  
**Answer**: `http://sploitme.com.cn/fg/load.php`

## 4. Geo-based Targeting Packet (Google France redirect)
```bash
tshark -r NukeTheBrowser.pcap -Y 'http.response.code >= 300 && http.location contains "google"' -T fields -e frame.number -e http.location
tshark -r NukeTheBrowser.pcap -Y 'http.response.code >= 300 && http.location contains "fr"' -T fields -e frame.number -e http.location
```
**Filter**: `http.location contains "google"`  
**Answer**: [Packet number from output]

## 5. CMS for 'shop.honeynet.sg/catalog/'
**Filters**: 
- `http.host contains "shop.honeynet.sg"`
- `http.request.uri contains "/catalog/"`  
- `frame contains "/catalog"`  
**Answer**: `osCommerce Online Merchant`

## 6. Packet Indicating 'show.php' Won't Re-infect
```bash
tshark -r NukeTheBrowser.pcap -Y 'http.request.uri contains "show.php"' -T fields -e frame.number -e http.request.uri
```
**Filter**: `http.request.uri contains "show.php"`  
**Answer**: [Packet number from output]

## 7. msdds.dll Vulnerability CVE
**Answer**: `cve-2005-2127`

## 8. Executable from 'http://sploitme.com.cn/fg/load.php?e=8'
**Answer**: `e.exe`

## 9. Full MD5 Hash (VirusTotal submission 2010-02-17, ends with '78873f791')
**Method**: HTTP → Export file → `.php` file → Compute MD5  
**Answer**: [Full MD5 hash]

## 10. Shellcode Function for 'http://sploitme.com.cn/fg/load.php?e=3'
**Answer**: `aolwinamp`

## 11. Deobfuscated JS 'rapidshare.com.eyu32.ru/login.php' → 'click' parameter
**Filter**: `frame contains "rapidshare.com.eyu32.ru/login.php"`  
**Answer**: [click parameter value]

## 12. mingw-gcc Version
**Filter**: `frame contains "gcc"`  
**Answer**: `3.4.5`

## 13. urlmon.dll Function for File Download
**Answer**: `URLDownloadToFile`

---

## Useful tshark Commands

### List Unique IPs
```bash
tshark -r NukeTheBrowser.pcap -T fields -e ip.src -e ip.dst | sort | uniq
```

### Protocol Hierarchy
```bash
tshark -r NukeTheBrowser.pcap -q -z io,phs
```

### HTTP Requests
```bash
tshark -r NukeTheBrowser.pcap -Y http.request
```

### Extract URLs
```bash
tshark -r NukeTheBrowser.pcap -Y http.request -T fields -e http.host -e http.request.uri
```

### DNS Queries
```bash
tshark -r NukeTheBrowser.pcap -Y dns -T fields -e dns.qry.name
```

### Failed DNS / Weird Domains
```bash
tshark -r NukeTheBrowser.pcap -Y "dns.flags.rcode != 0"
```

### Suspicious File Downloads
```bash
tshark -r NukeTheBrowser.pcap -Y "http.response.code == 200"
```

### Look for Executables
```bash
tshark -r NukeTheBrowser.pcap -Y 'http contains ".exe"'
```

### User-Agent
```bash
tshark -r NukeTheBrowser.pcap -Y http.request -T fields -e http.user_agent
```

### POST Requests
```bash
tshark -r NukeTheBrowser.pcap -Y "http.request.method == POST"
```

### Follow TCP Streams
```bash
tshark -r NukeTheBrowser.pcap -q -z follow,tcp,ascii,0
```

### Top Talkers
```bash
tshark -r NukeTheBrowser.pcap -q -z endpoints,ip
```

### Conversations
```bash
tshark -r NukeTheBrowser.pcap -q -z conv,ip
```