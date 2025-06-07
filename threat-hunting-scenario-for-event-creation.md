Threat Event (Unauthorized Credential Dumping)
Mimikatz Credential Dumping Executed by Insider

Reason for the Hunt
Unusual system behavior was reported: the Security Operations Center (SOC) observed multiple alerts related to suspicious access to LSASS memory. In parallel, recent cybersecurity reports have highlighted a surge in the use of Mimikatz during the post-exploitation phase of ransomware campaigns.
In response, management has issued a directive to proactively hunt for signs of credential dumping across all corporate endpoints.

Steps the "Bad Actor" Took to Create Logs and IoCs
Transferred Invoke-Mimikatz.ps1 to the desktop of the target system.

Executed the script using PowerShell with execution policy bypass:

powershell
Copy
Edit
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-Mimikatz.ps1
Dumped credentials from LSASS memory using:

powershell
Copy
Edit
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
Stored the dumped credentials in:

vbnet
Copy
Edit
C:\Users\Public\dumped-creds.txt
Exfiltrated the file using a cloud sync folder (e.g., OneDrive) or by sending it via email.

Tables Used to Detect IoCs
Name	Description
DeviceProcessEvents	Link
Used to detect PowerShell usage, suspicious command-line flags, and Mimikatz indicators.
DeviceFileEvents	Link
Used to detect script transfer, creation of the output file, or interaction with sensitive paths.
DeviceNetworkEvents	Link
Used to check for exfiltration attempts to external services or sync clients.

Related Queries
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
Created By
Author Name: ChatGPT (based on real-world TTPs)

Author Contact: https://openai.com

Date: June 6, 2025

Validated By
Reviewer Name: [To be filled in]

Reviewer Contact: [To be filled in]

Validation Date: [To be filled in]

