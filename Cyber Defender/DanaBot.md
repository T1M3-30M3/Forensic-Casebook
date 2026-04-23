# Cyber Attack Forensics Report

## 🌐 Initial Access Details

### **Which IP address was used by the attacker during the initial access?**
```
10.2.14.101 → 62.173.142.148 with GET /login.php
62.173.142.148 → 10.2.14.101 with HTTP/1.1 200 OK
Attacker IP (Client): 10.2.14.101
Server IP: 62.173.142.148

Traffic: 10.2.14.101 → 62.173.142.148 (GET /login.php)
Response: 62.173.142.148 → 10.2.14.101 (HTTP/1.1 200 OK)
Filters: ip.dst == 10.2.14.101 | ip.addr == 10.2.14.101 && http
```

### **What is the name of the malicious file used for initial access?**
```
Filename: allegato_708.js
Content-Type: application/octet-stream
SHA-256: 847B4AD90B1DABA2D9117A8E05776F3F902DDA593FB1252289538ACF476C4268
Delivery: http.response && http.content_type == "application/octet-stream"
```

### **Which process was used to execute the malicious file?**
```
Process: wscript.exe
Purpose: Executes JavaScript malicious payload (allegato_708.js)
```

## 🔄 Second Stage Payload

### **Second Malicious File**
```
Extension: .dll
MD5 Hash: e758e07113016aca55d9eda2b0ffeebe
```

## 📊 Traffic Analysis Filters
```
Statistics → IPv4 Statistics → All Addresses
http.request.method == POST
http.request.method == GET  
ip.addr == 10.2.14.101 && (ftp || smb || smtp)
ip.addr == 10.2.14.101 && http
```

---

## 🛡️ **Immediate Response Actions**

```powershell
# 1. Block Attacker IP
netsh advfirewall firewall add rule name="Block_Attacker" dir=in action=block remoteip=10.2.14.101

# 2. Hash IOCs for Detection
SHA256: 847B4AD90B1DABA2D9117A8E05776F3F902DDA593FB1252289538ACF476C4268
MD5:    e758e07113016aca55d9eda2b0ffeebe

# 3. Kill Malicious Processes
taskkill /f /im wscript.exe

# 4. Quarantine Files
del allegato_708.js *.dll (matching MD5)
```

**Attack Chain**: `JS (wscript.exe) → DLL (persistence)`  
**TTPs**: Spear-phishing → Fileless execution → DLL side-loading