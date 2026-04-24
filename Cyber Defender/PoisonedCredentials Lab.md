# Network Security Incident Investigation Guide

## 1. Identifying the Mistyped Query from Legitimate Machine

**Question**: In the context of the incident, the attacker initiated actions by taking advantage of benign network traffic from legitimate machines. Identify the specific mistyped query made by the machine with IP `192.168.232.162`.

**Filters**:
```
ip.addr == 192.168.232.162
dns.qry.name
llmnr and ip.src == 192.168.232.162
```

**Answer**: `fileshaare`

## 2. Identifying the Rogue Machine IP Address

**Question**: Determine the IP address of the rogue machine acting as the rogue entity.

**Filters & Commands**:
```
dns.qry.name
nbns.flags.response == 1
llmnr and ip.src == 192.168.232.215
```

**Analysis Command**:
```bash
tshark -r capture.pcapng -Y "llmnr.flags.response == 1 || nbns.flags.response == 1" -T fields -e ip.src | sort | uniq -c | sort -nr
```

## 3. Identifying Affected Machines (Second Machine Receiving Poisoned Responses)

**Question**: What is the IP address of the second machine that received poisoned responses from the rogue machine?

**Filters**:
```
dns.qry.name
ip.src == 192.168.232.215 && (llmnr || nbns)
```

**Analysis Command**:
```bash
tshark -r capture.pcapng -Y "ip.src == 192.168.232.215 && (llmnr || nbns)" -T fields -e ip.dst | sort -u
```

## 4. Identifying the Compromised Username

**Question**: Determine the username associated with the compromised account.

**Filters**:
```
ntlmssp
ntlmssp && ip.src == 192.168.232.215
ntlmssp && ip.addr == 192.168.232.215
```

## 5. Identifying the Attacker's SMB Target Hostname

**Question**: What is the hostname of the machine that the attacker accessed via SMB?

**Filter Path**:
```
SMB2 > Session Setup Request (0x01) > Security Blob > GSS-API Generic Security Service Application Program Interface > negTokenTarg > NTLM Secure Service Provider > NTLM Response > NTLMv2 Response
```

## Basic Investigation Commands

### LLMNR Traffic Analysis
```bash
# All LLMNR traffic
tshark -r capture.pcapng -Y "llmnr"

# LLMNR responses with source IP and query name
tshark -r capture.pcapng -Y "llmnr.flags.response == 1" -T fields -e ip.src -e llmnr.qry.name

# Unique LLMNR query names
tshark -r capture.pcapng -Y "llmnr" -T fields -e llmnr.qry.name | sort -u
```

### NBT-NS Traffic Analysis
```bash
# All NBT-NS traffic
tshark -r capture.pcapng -Y "nbns"

# NBT-NS responses with source IP and name
tshark -r capture.pcapng -Y "nbns.flags.response == 1" -T fields -e ip.src -e nbns.name

# Unique NBT-NS names
tshark -r capture.pcapng -Y "nbns" -T fields -e nbns.name | sort -u
```

### NTLM Traffic Analysis
```bash
# All NTLM traffic
tshark -r capture.pcapng -Y "ntlmssp"

# Extract usernames from NTLM authentication
tshark -r capture.pcapng -Y "ntlmssp.auth.username" -T fields -e ntlmssp.auth.username
```

## Investigation Summary

| Investigation Step | Key IP Addresses | Protocols | Key Indicators |
|-------------------|------------------|-----------|---------------|
| Mistyped Query | 192.168.232.162 | LLMNR/DNS | `fileshaare` |
| Rogue Machine | 192.168.232.215 | LLMNR/NBNS | Poisoned responses |
| Affected Machines | Multiple | LLMNR/NBNS | Responses from rogue |
| Compromised Account | N/A | NTLM | Authentications |
| SMB Access | N/A | SMB2/NTLM | Session Setup Requests |

**Attack Flow**: Legitimate machine (192.168.232.162) → Mistyped query (`fileshaare`) → Rogue machine (192.168.232.215) poisons response → Multiple victims receive poisoned responses → NTLM auth → SMB access to target hostname.