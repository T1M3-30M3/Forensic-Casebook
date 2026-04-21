# Digital Forensics Workflow: Clean & Sorted Guide

## 🛠️ **Tools Required**
```
Autopsy | DCode | FTK Imager | JumpListExplorer | Registry Explorer
SQLite DB Browser | SysTools Outlook PST Viewer | WinPrefetchView | Registry Viewer
```

## 📁 **Step 1: Evidence Extraction (FTK Imager)**
```
1. File → Add Evidence Item → Choose Image File
2. Browse contents → Right-click → Export Files → Save to folder
3. Autopsy → New Case → Data Source → Logical Files → [Extracted Folder]
```

## 🖥️ **System Identification (Registry Analysis)**

### **Computer Name**
```
Registry Path: HKLM\SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName
File: Windows\System32\config\SYSTEM
Registry Viewer: ControlSet001\Control\ComputerName\ComputerName
```

### **Computer IP Address**
```
Registry Path: ControlSet001\Services\Tcpip\Parameters\Interfaces\<GUID>
Keys: IPAddress, DhcpIPAddress
```

### **DHCP Lease Time**
```
Registry Path: ControlSet001\Services\Tcpip\Parameters\Interfaces\<GUID>
Key: LeaseObtainedTime
```

### **Computer SID**
```
Registry Path: Software\Microsoft\Windows NT\CurrentVersion\ProfileList
```

### **Operating System Version**
```
Registry Path: SOFTWARE\Microsoft\Windows NT\CurrentVersion
```

### **Computer Timezone**
```
Registry Path: System\ControlSet001\Control\TimeZoneInformation
```

### **User Logons**
```
Registry Path: SAM\Domains\Account\Users
```

## 🔒 **Event Log Analysis (Security Events)**

### **Extract Security Logs**
```
FTK Imager: Windows\System32\winevt\Logs → Export Files → Security.evtx
```

### **Event Log Parsing (EvtxECmd)**
```
# CSV Output (All Events)
EvtxECmd.exe -f Security.evtx --csv Securityevents.csv

# CSV Output (Logon Events Only - Event ID 4624)
EvtxECmd.exe -f Security.evtx --csvf Securityevents.csv --inc 4624

# JSON Output
EvtxECmd.exe -f "Security.evtx" --json "OutputPath"
```

## 📋 **Quick Reference Table**

| **Artifact** | **Registry Hive** | **Key/Path** |
|--------------|------------------|-------------|
| Computer Name | SYSTEM | ControlSet001\Control\ComputerName |
| IP Address | SYSTEM | ControlSet001\Services\Tcpip\Parameters\Interfaces |
| DHCP Lease | SYSTEM | ControlSet001\Services\Tcpip\Parameters\Interfaces\<GUID> |
| Computer SID | SOFTWARE | Microsoft\Windows NT\CurrentVersion\ProfileList |
| OS Version | SOFTWARE | Microsoft\Windows NT\CurrentVersion |
| Timezone | SYSTEM | ControlSet001\Control\TimeZoneInformation |
| User Accounts | SAM | SAM\Domains\Account\Users |

