# PacketDetective CTF Solutions

## SMB Protocol Bytes
**Question:** What is the total number of bytes of the SMB protocol?  
**Path:** Statistics → Protocol Hierarchy → smb || smb2 then Statistics → Conversations → TCP or Statistics → Summary  
**Answer:** [Bytes value from statistics]

## SMB Authentication Username
**Question:** Which username was utilized for authentication via SMB?  
**Filter:** `ntlmssp.auth.username`  
**Answer:** [Username from filter]

## File Accessed by Attacker
**Question:** What is the name of the file that was opened by the attacker?  
**Filter:** `smb search eventlog, ClearEventLog, ElfrClearELFW`  
**Path:** `path : eventlog`  
**Answer:** `eventlog`

## Event Log Clearing Timestamp
**Question:** What is the timestamp of the attempt to clear the event log? (24-hour UTC format)  
**Answer:** `2020-09-23 16:50`

## Named Pipe Service
**Question:** What is the name of the service that communicated using this named pipe?  
**Filter:** `frame contains 5c:00:50:00:49:00:50:00:45` (to find `\PIPE\`)  
**Answer:** `atsvc`

## Communication Duration
**Question:** What was the duration of communication between the identified addresses 172.16.66.1 and 172.16.66.36?  
**Path:** Statistics → Conversations  
**Filter:** `ip.addr == 172.16.66.1 and ip.dst == 172.16.66.36`  
**Answer:** [Duration from conversations]

## Suspicious Username for Requests
**Question:** Which username was used to set up these potentially suspicious requests?  
**Filter:** `ntlmssp` or `ntlmssp_auth`  
**Answer:** [Username from NTLMSSP]

## Event ID (Solved)
**Question:** [Related to event ID]  
**Answer:** `4763`

## Remote Process Execution File
**Question:** What is the name of the executable file utilized to execute processes remotely?  
**Filter:** `smb2`  
**Answer:** `PSEXESVC`