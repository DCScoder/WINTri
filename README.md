# WINTri
Windows Cyber Security Incident Response Script

#### Description:

The purpose of this script is to preserve and collect notable Windows artefacts. Once dropped onto the target system, the script will utilise a series of internal commands to query information from the host and retrieve data, which it stores in a temporary folder. Once all data has been collected, all files are hashed with the MD5 algorithm and the hash values are retained in a log file. Finally, the collection is archived into a ZIP file and the temporary store is deleted. The ZIP file can then be retrieved by the analyst for subsequent analysis offline. The script should be used during fast-time collection and preservation of artefacts during a cyber security incident. Frequent progress updates are provided in English and German languages via the terminal, whilst the script is active. A log of the terminal activities is also created and retained in the archive collection.

#### Artefacts Supported:

Memory:

- Process List
- Process & Services
- Process & Loaded DLL
- Process & Owners

Registry:

- Local Groups
- Local Users
- Local Admins
- Domain Admins
- Enterprise Admins
- SYSTEM Hive
- SOFTWARE Hive
- SAM Hive
- SECURITY Hive
- .DEFAULT Hive
- NTUSER.DAT
- UsrClass

Logs:

- Windows Event Logs
- USB Device Connection Logs
- Windows Update Logs
- Powershell Console History Logs
- Firewall Logs
- Internet Information Services (IIS) Logs
- Exchange Logs
- User Access Logging (UAL)

Network:

- DNS Entries
- Network Settings
- IP Configuration
- Local DNS
- DNS Client Cache
- ARP Table
- Netstat
- Routing Table
- Listening Ports
- Open Connections
- Wireless Profiles
- Firewall Configurations
- Firewall Profile Properties
- Firewall Rules

Configuration:

- Screenshot
- Operating System Information
- System Date/Time
- Environment Variables
- AntiVirus Product
- Anti Malware Health Status
- Hotfixes
- Disk Management
- Server Message Block (SMB) Shares
- Scheduled Tasks
- WMI Filters
- WMI Consumers
- WMI Bindings
- Volume Shadow Copy Service (VSC/VSS)
- Group Policy

File System:

- Alternate Data Streams (ADS)
- Perflogs Directory Listing
- Root Temp Directory Listing
- Windows Temp Directory Listing
- AppData Temp Directory Listing
- Downloads Directory Listing
- Named Pipes

Operating System:

- Installed Programs
- Startup Programs
- Startup Files
- Server Message Block (SMB) Sessions
- BITSAdmin Job Que
- RDP Cache
- System Resource Usage Monitor (SRUM)
- Windows Notifications
- Prefetch
- Recent File Cache
- Amcache
- Program Compatibility Assistant (PCA)
- LNK
- Jumplists
- Windows Timeline
- Cryptnet URL Cache Metadata

Internet:

- Chrome
- FireFox
- IE

#### Usage:

Step 1: Copy script to target host.

Step 2: Execute script with Administrator priveleges:

```
.\WINTri.ps1
```

If issues are encountered relating to PowerShell policies, instead of using 'Set-ExecutionPolicy' to change the policy, utilise a batch script to bypass and execute:

```
powershell.exe -ExecutionPolicy Bypass -File C:\<path_to_script>\WINTri.ps1
```

Step 3: Download resultant (*.zip) archive file via your preferred method.

Step 4: Delete script and archive file from host:

```
Remove-Item -Path C:\<path_to_script>\WINTri.ps1
```
```
Remove-Item -Path C:\<path_to_archive>\WINTri_<hostname>_<date>_<time>.zip
```

#### Requirements:

- Script must be run with local Administrator priveleges.
- Ensure local PowerShell policies permit execution.
- Several standard built-in Windows tools are leveraged. No third-party tools are required.
- As the script interacts with sensitive Windows registry hives, configure an exclusion path and add hash value to a whitelist on any AV/EDR tools, to allow the script to execute fully.
