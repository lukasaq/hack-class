Here are all the PowerShell commands found in the file m11-m15_dump .md from the lukasaq/hack-class repository, along with syntax examples and any switches or parameters used:

---

### WMI / CIM Commands

#### 1. Get-WmiObject
- Lists all available WMI classes:
  ```powershell
  Get-WmiObject -List
  ```
- Alias: gwmi

#### 2. Get-CimInstance
- Lists services that start automatically at boot:
  ```powershell
  Get-CimInstance Win32_service -Filter "StartMode = 'Auto'" | Select-Object Name, StartMode, PathName
  ```
- Displays all available fields of a class:
  ```powershell
  Get-CimInstance Win32_BIOS | Get-Member
  ```
- Filters processes by name (example: powershell.exe):
  ```powershell
  Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'"
  ```
- Lists disabled services:
  ```powershell
  Get-CimInstance Win32_service -Filter "StartMode = 'Disabled'" | Select-Object Name, StartMode
  ```
- Gets BIOS info from a remote host:
  ```powershell
  Invoke-Command -ScriptBlock {Get-CimInstance Win32_Bios | Select-Object ReleaseDate} -ComputerName 172.16.4.2 -Credential $creds
  ```
- Gets local OS build number:
  ```powershell
  Get-CimInstance Win32_OperatingSystem | Select-Object BuildNumber
  ```
- Accesses remote process information:
  ```powershell
  Get-CimInstance -ClassName Win32_Process -ComputerName Server64
  ```
- Using -Property to select specific fields:
  ```powershell
  Get-CimInstance -ClassName Win32_BIOS | Select-Object -Property SerialNumber
  Get-CimInstance -ClassName Win32_BIOS | Select-Object -Property SerialNumber, Version
  ```
- Accesses multiple remote hosts:
  ```powershell
  Get-CimInstance Win32_Service -Filter "Name = 'VSS'" -ComputerName RemoteHost,RemoteHost2,RemoteHost3 -Credential $credentials
  ```
- Example with Format-Table and Out-File:
  ```powershell
  Get-CimInstance Win32_OperatingSystem | select-object CSName, Caption | Format-Table -HideTableHeaders | Out-File C:\Users\Trainee\Desktop\hostname-os.txt -Append
  ```

#### 3. Get-WmiObject with -Query (WQL)
- Queries with WMI Query Language:
  ```powershell
  Get-WmiObject -Query "Select * from Win32_Bios"
  Get-WmiObject -Query "select * from win32_process where name='notepad.exe'" | Remove-WmiObject
  Get-WMIObject -Query "Select * From Win32_Directory Where Name ='C:\\Test'" | Remove-WMIObject
  Get-WMIObject -query "select * from CIM_DataFile where Name = 'C:\\malware.exe'"
  ```

#### 4. Get-Member
- Lists members/fields of a WMI/CIM object:
  ```powershell
  Get-CIMinstance Win32_BIOS | Get-Member
  ```

---

### PowerShell Cmdlet Discovery

#### 5. Get-Command
- Lists all WMI Cmdlets:
  ```powershell
  Get-Command -Noun WMI*
  ```
- Lists all CimCmdlets:
  ```powershell
  Get-Command -Module CimCmdlets
  ```

---

### Remote Execution and Scripting

#### 6. Invoke-Command
- For running commands/scripts on remote computers:
  ```powershell
  Invoke-Command -ScriptBlock {Get-CimInstance Win32_Bios | Select-Object ReleaseDate} -ComputerName 172.16.4.2 -Credential $creds
  Invoke-Command -ComputerName 172.16.4.2 -ScriptBlock {Get-CimInstance -Namespace root\subscription -Class __EventConsumer} -Credential $creds
  Invoke-Command -ComputerName 172.16.4.9 -ScriptBlock {Get-CimInstance -Namespace root\subscription -Class __EventConsumer} -Credential $creds
  Invoke-Command -scriptblock {Get-CimInstance Win32_OperatingSystem | select-object CSName, Caption | Format-Table -HideTableHeaders} -Credential $creds
  ```

#### 7. Import-Module
- Loads a PowerShell module (example for remote management):
  ```powershell
  Import-Module C:\Users\Trainee\Desktop\Lab.ps1
  ```

#### 8. Get-Content
- Reads content from a file (used in scripting for hostnames):
  ```powershell
  Get-Content C:\users\trainee\Desktop\hosts.csv
  ```

---

### File and Process Management

#### 9. Remove-WmiObject
- Stops a process or deletes a file/directory via WMI:
  ```powershell
  Get-WmiObject -Query "select * from win32_process where name='notepad.exe'" | Remove-WmiObject
  Get-WMIObject -Query "Select * From Win32_Directory Where Name ='C:\\Test'" | Remove-WMIObject
  ```

---

### Filtering and Output Formatting

#### 10. Select-Object
- Filters and selects specific object properties:
  ```powershell
  Select-Object Name, StartMode, PathName
  Select-Object -Property SerialNumber
  Select-Object -ExpandProperty message
  ```

#### 11. Sort-Object
- Sorts output based on a property:
  ```powershell
  Sort-Object HandleCount
  ```

#### 12. Format-Table and Format-List
- Formats output as a table or list:
  ```powershell
  Format-Table -HideTableHeaders
  Format-List
  ```

#### 13. Select-String
- Searches for text patterns in output:
  ```powershell
  select-string -Pattern '(Account Name:)(.*)' -All
  select-string -Pattern '(Process Name:)(.*)' -All
  ```

#### 14. Out-File
- Writes output to a file:
  ```powershell
  Out-File C:\Users\Trainee\Desktop\hostname-os.txt -Append
  ```

---

### Event Log Queries

#### 15. Get-WinEvent
- Gets Windows event logs, filters with hashtable:
  ```powershell
  Get-winevent -MaxEvents 200 -filterhashtable @{logname="security";id="4624"}|select-object -expandproperty message
  ```

---

### Parameters and Switches Observed

- -List (lists WMI classes)
- -Filter "..." (filters WMI/CIM objects)
- -Query "..." (WQL queries)
- -Class / -ClassName (specifies WMI/CIM class)
- -Property (limits returned properties)
- -ExpandProperty (returns only the property value)
- -ComputerName (specifies remote computer)
- -Credential (specifies credentials for remote access)
- -Module (specifies module to import)
- -Noun (filters cmdlets by noun)
- -MaxEvents (limits number of events)
- -HideTableHeaders (removes table headers from output)
- -Append (appends output to file)
- -Namespace (specifies WMI namespace)
- -ScriptBlock (provides a script block for remote execution)
- -All (in Select-String, matches all occurrences)

---

If you need explanations or details for any specific command or switch, let me know!
