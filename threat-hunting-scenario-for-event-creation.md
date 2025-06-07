🔐 Threat Event: Unauthorized Credential Dumping
Mimikatz Credential Dumping Executed by Insider
📌 Reason for the Hunt
Unusual system behavior was reported: the Security Operations Center (SOC) observed multiple alerts related to suspicious access of LSASS memory.

In parallel, cybersecurity intelligence reports have highlighted a rise in the use of Mimikatz in the post-exploitation phase of ransomware campaigns.

🔧 As a result, management has directed a proactive threat hunt across all endpoints for credential dumping activity.

🧰 Steps the "Bad Actor" Took to Create Logs and IoCs
Transferred the file Invoke-Mimikatz.ps1 to the desktop of the victim system.

Executed the script via PowerShell using an execution policy bypass:

powershell
Copy
Edit
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-Mimikatz.ps1
Dumped credentials from LSASS memory using:

powershell
Copy
Edit
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
Stored the output in:

plaintext
Copy
Edit
C:\Users\Public\dumped-creds.txt
Exfiltrated the file using a cloud sync folder (e.g., OneDrive) or sent via email.

📊 Tables Used to Detect IoCs
🔍 Table Name	📝 Description
DeviceProcessEvents	Link
Detects PowerShell usage with suspicious flags and Mimikatz indicators.
DeviceFileEvents	Link
Detects script placement, file creation, and output dumps.
DeviceNetworkEvents	Link
Detects potential exfiltration via cloud or network activity.

🧠 Related KQL Queries
kql
Copy
Edit
// PowerShell invoking Mimikatz
DeviceProcessEvents
| where ProcessCommandLine contains "Invoke-Mimikatz"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName

// PowerShell execution policy bypass
DeviceProcessEvents
| where ProcessCommandLine has "ExecutionPolicy Bypass"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Common credential dumping keywords
DeviceProcessEvents
| where ProcessCommandLine has_any("sekurlsa::logonpasswords", "sekurlsa::msv")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine

// Mimikatz script placed or accessed
DeviceFileEvents
| where FileName contains "Invoke-Mimikatz.ps1"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType

// Dumped credentials file created or modified
DeviceFileEvents
| where FileName contains "dumped-creds"
| project Timestamp, DeviceName, FileName, ActionType, InitiatingProcessFileName

// Credential dump exfiltrated via sync folder
DeviceFileEvents
| where FolderPath has "OneDrive"
| where FileName contains "dumped-creds"
| project Timestamp, DeviceName, FileName, FolderPath, ActionType
