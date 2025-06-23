# threat-hunt-scenario-suspicious-rdp-login

# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project
<img width="420" alt="Screen Shot 2025-06-23 at 6 48 22 AM" src="https://github.com/user-attachments/assets/82097391-d0fa-4572-8eb9-b10ec41fc2b2" />

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)


##  Scenario

Security Operations detected multiple successful Remote Desktop Protocol (RDP) logins to internal systems originating from non-corporate IP addresses. Some of these logins came from geolocations inconsistent with employee travel records.

In response to a recent CISA advisory on brute-force RDP attacks, management has directed a proactive threat hunt to identify signs of RDP misuse or unauthorized access.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceLogonEvents`** for any signs of successful RDP logins from suspicious locations.
- **Check `DeviceFileEvents`** for any commonly used files such as `anydesk`, `7zip` or `mimikatz` file events.
- **Check `DeviceProcessEvents`** for any of the above files being executed.

---

## Steps Taken

### 1. Searched the `DeviceLogonEvents` Table

Searched for any LogonEvents that were of the Remoteinteractive type, meaning someone logged in away from the company network. All of the logs discovered showed no suspicious Remote IP addresses.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName == "jeffreywindows1"
| where LogonType == "RemoteInteractive"
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType
```
<img width="1277" alt="Screen Shot 2025-06-22 at 8 43 15 AM" src="https://github.com/user-attachments/assets/27b4b698-f70a-4d1c-8bd0-ac44f43f8dea" />

---

### 2. Searched the `DeviceNetworkEvents` Table for foreign or knowm Suspicous IP ranges

Searched for Device Network events that used RemotePort 3389 and that omitted IP ranges that start with `10.` or `192.168` as these are good IP ranges. This search returned no results.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where RemotePort == 3389
| where RemoteIP !startswith "192.168." and RemoteIP !startswith "10."
| where DeviceName == "jeffreywindows1"
| project Timestamp, ActionType, DeviceName, InitiatingProcessAccountName, RemoteIP, RemotePort```
```

<img width="1095" alt="Screen Shot 2025-06-22 at 8 47 25 AM" src="https://github.com/user-attachments/assets/eebcf4de-e475-4b03-806f-a20b0b7daacc" />

---

### 3. Searched the `DeviceNetworkEvents` Table for LogonSuccess events to the workstation "JeffreyWindows1"

Searched for Device Network events that resulted in LogonSuccess to this workstation.

**Query used to locate events:**

```kql
DeviceLogonEvents
| where DeviceName == "jeffreywindows1" 
| where ActionType == "LogonSuccess" 
| order by Timestamp desc
| where RemoteIP != "" and RemoteIP !in ("10.0.8.8", "10.0.8.6", "10.0.8.7", "10.0.8.5")
| project Timestamp, DeviceName, AccountName, RemoteIP, LogonType
```

<img width="1329" alt="Screen Shot 2025-06-22 at 8 51 22 AM" src="https://github.com/user-attachments/assets/4c77de51-8d4e-45f8-b173-c059394ca7ab" />

---

### 4. Searched the `DeviceFileEvents` Table for Different Common files that can be used maliciously.

Searched for Device File Events for any of these common files: "mimikatz.exe", "winPE.zip", ".7z", "procdump.exe", "anydesk.exe"

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "jeffreywindows1"
| where FileName has_any ("mimikatz.exe", "SharpHound.exe", "netcat.exe", "psexec.exe", "powershell.exe")
| project Timestamp, ProcessCommandLine, InitiatingProcessCommandLine, InitiatingProcessFolderPath
```

This query showed that several different files were downloaded by the malicious user, probably to steal credentials (mimikatz) and reconaissance (anydesk).

<img width="1311" alt="Screen Shot 2025-06-23 at 6 33 32 AM" src="https://github.com/user-attachments/assets/af618f9d-fbab-4174-8301-1dd1de799638" />

---

### 5. Searched the `DeviceProcessEvents` Table to see if 7Zip, Procdump or AnyDesk were launched after being downloaded.

Verified this by inspecting the ProcessCommandLine column, found no evidence of any of these programs being launched. 

```kql
DeviceProcessEvents
| where DeviceName == "jeffreywindows1" 
| project Timestamp, ProcessCommandLine
```

---



## Chronological Event Timeline 

### 1. Successful Suspicious RDP Logon 

- **Timestamp:** `2025-06-12T09:57:54.4183306Z`
- **Event:** A user logged onto the "jeffreywindows1" workstation using the correct credentials for the user "fryecyber12345!" from the IP address `50.173.17.242`

---

### 2. Anydesk.exe file downloaded 

- **Timestamp:** `2025-06-12T10:05:38.3669674Z`
- **Event:** The suspicious user downloaded the file "Anydesk.exe" which can be used for remote control execution or credential theft. The file path is obviously suspicious as it is stored under the "SuspicousToolsLab" folder on the C drive. 
- - **Action:** File download detected.
- **File Path:** `C:\SuspiciousToolsLab\AnyDesk.exe`

---



## Summary

The suspicious user sucessfully logged in and downloaded `Anydesk.exe` but never launched it. It appears this user was waiting for the right time to launch the program and most likely use it as a persistence mechanicsm. 

---

## Response Taken

The program `anydesk.exe` was downloaded by the user `fryecyber12345!` on the workstation `jeffreywindows1`. Someone obtained this users credentials in an unkown fashion as the IP address was not in our corporate range and the real user, Jeffrey Frye, is trustworthy and denies downloading that file.  The device was isolated, and the user's direct manager was notified.

---
