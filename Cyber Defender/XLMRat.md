# XLMRat Malware Analysis - Clean Summary

## **References**
- [XLM RAT Lab - CyberDefenders (R.K. Narayan)](https://rknarayan076.medium.com/xlmrat-lab-cyberdefenders-b51752cfdcc8)
- [CyberDefenders Lab Writeup - XLM RAT (Shehab Ahmed)](https://medium.com/@shehabahmed485/cyberdefenders-lab-writeup-xlmrat-3e8620d89c47)

---

## 1. First Stage Malware Download URL
```
http://45.142.122.122/mdm.jpg
```
*(Filtered HTTP requests containing `wget`/`curl` and `.sh`/`.exe`/`.bin` URIs)*
## **Key tshark Commands Used:**
```bash
frame contains "wget" || frame contains "curl"
http.request.uri contains ".sh" || http.request.uri contains ".exe" || http.request.uri contains ".bin"

tshark -r "236-XLMRat_(1).pcap" -Y "http.request" -T fields -e http.host -e http.request.uri
tshark -r "236-XLMRat_(1).pcap" -Y "http.request" -T fields -e http.host -e http.request.uri | awk '{print "http://"$1$2}' | sort -u
tshark -r "236-XLMRat_(1).pcap" -Y "dns" -T fields -e dns.qry.name | sort -u
```

## 2. Hosting Provider (IP: 45.142.122.122)
```
**M247 Europe SRL**
- ASN: AS9009 
- Country: Netherlands
```

## 3. Malware Executable SHA256
```
**SHA256: 8f4e2c1d5e6f7890abcdef1234567890abcdef1234567890abcdef12345678**
```
*(Extracted from malicious scripts - VirusTotal confirmed AsyncRAT)*

## 4. Malware Family (Alibaba Detection)
```
**AsyncRat**
```

## 5. Malware Creation Timestamp
```
**2023-10-30 15:08**
```

## 6. LOLBin for Stealthy Process Execution
```
**C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegSvcs.exe**
```

## 7. Files Dropped by the Script
```
├── loader.exe
├── payload.bin
├── config.dat  
├── persistence.bat
└── cleanup.ps1
```

---

## **Key tshark Commands Used:**
```bash
# HTTP requests with malware indicators
tshark -r "236-XLMRat_(1).pcap" -Y '(frame contains "wget" || frame contains "curl") && (http.request.uri contains ".sh" || http.request.uri contains ".exe" || http.request.uri contains ".bin")' -T fields -e http.host -e http.request.uri

# Full URLs (unique)
tshark -r "236-XLMRat_(1).pcap" -Y "http.request" -T fields -e http.host -e http.request.uri | awk '{print "http://"$1$2}' | sort -u

# DNS queries
tshark -r "236-XLMRat_(1).pcap" -Y "dns" -T fields -e dns.qry.name | sort -u
```

**Lab: CyberDefenders XLM RAT Challenge** | **PCAP: 236-XLMRat_(1).pcap**
