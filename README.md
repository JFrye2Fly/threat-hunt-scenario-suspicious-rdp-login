# threat-hunt-scenario-suspicious-rdp-login

# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

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

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2024-11-08T22:27:19.7259964Z`. These events began at `2024-11-08T22:14:48.6065231Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName == "employee"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2024-11-08T22:14:48.6065231Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/71402e84-8767-44f8-908c-1805be31122d">

---


## Chronological Event Timeline 

### 1. Successful Suspicious RDP Logon 

- **Timestamp:** `2025-06-12T09:57:54.4183306Z`
- **Event:** A user logged onto the "jeffreywindows1" workstation using the correct credentials for the user "fryecyber12345!" from the IP address `50.173.17.242`

### 2. Successful Suspicious RDP Logon 

- **Timestamp:** `2025-06-12T09:57:54.4183306Z`
- **Event:** A user logged onto the "jeffreywindows1" workstation using the correct credentials for the user "fryecyber12345!" from the IP address 50.173.17.242
- - **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

---

## Summary

The...

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
