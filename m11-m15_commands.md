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
