# 🔍 Threat Hunt: Unauthorized RDP Access

## 📌 Event Summary
**Remote Desktop Connection from Unapproved External IP Address**

---

## 🎯 Hunt Justification

Security Operations detected multiple successful Remote Desktop Protocol (RDP) logins to internal systems originating from **non-corporate IP addresses**. Some of these logins came from geolocations inconsistent with employee travel records. 

In response to a recent **CISA advisory on brute-force RDP attacks**, management has directed a proactive threat hunt to identify signs of RDP misuse or unauthorized access.

---

## 🧱 Steps Taken by the Threat Actor (Based on Logs and IoCs)

1. **Obtained valid employee credentials**  
   _Possible methods:_ phishing, password spraying, or credential leaks (e.g., via dark web).

2. **Initiated RDP session**  
   From an external IP address, often using residential VPNs or proxies to mask location.

3. **Successfully logged into a corporate workstation or server**

4. **Executed reconnaissance commands**  
   Tools used: `Task Manager`, `PowerShell`, or `cmd.exe` to enumerate processes, privileges, and files.

5. **Transferred files using shared folders or clipboard**  
   Examples: `mimikatz.exe`, `winPE.zip`, `anydesk.exe`

6. **Performed lateral movement**  
   Leveraged built-in Windows tools to access other systems.

---

## 📊 Tables Used to Detect IoCs

| Table Name             | Purpose                                                                                              | Documentation                                                                 |
|------------------------|------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------|
| `DeviceLogonEvents`    | Detects RDP logins (`LogonType == 10`) and tracks logon source IPs                                   | [Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table) |
| `DeviceNetworkEvents`  | Monitors inbound RDP traffic, flags connections from external or foreign IP addresses                | [Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) |
| `DeviceProcessEvents`  | Tracks execution of `PowerShell`, `cmd.exe`, `taskmgr.exe`, and post-login activity                  | [Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| `DeviceFileEvents`     | Detects file activity related to known offensive tools and compressed archives                       | [Link](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |

---

## 📐 Related KQL Queries

### 🔎 Detect Remote Logins (RDP: LogonType == 10)
```kql

DeviceLogonEvents
| where DeviceName == "jeffreywindows1"
| where LogonType == "RemoteInteractive"
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType

DeviceLogonEvents
| where DeviceName == "jeffreywindows1"
| where LogonType == "RemoteInteractive"
| where RemoteIP != "" and RemoteIP !in ("10.0.8.8", "10.0.8.6")
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType

DeviceProcessEvents
| where DeviceName == "jeffreywindows1"
| where FileName has_any ("mimikatz.exe", "SharpHound.exe", "netcat.exe", "psexec.exe", "powershell.exe")
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFolderPath

