Here are all the PowerShell commands and syntax examples from the file m11-m15_dump.md, with their switches and parameters grouped under their associated commands:

---

## 1. Get-WmiObject
- **Switches/Parameters:**
  - -List (lists WMI classes)
  - -Query "..." (WQL queries)
- **Examples:**
  ```powershell
  Get-WmiObject -List
  Get-WmiObject -Query "Select * from Win32_Bios"
  Get-WmiObject -Query "select * from win32_process where name='notepad.exe'" | Remove-WmiObject
  Get-WMIObject -Query "Select * From Win32_Directory Where Name ='C:\\Test'" | Remove-WMIObject
  Get-WMIObject -query "select * from CIM_DataFile where Name = 'C:\\malware.exe'"
  ```
  - Alias: gwmi

---

## 2. Get-CimInstance
- **Switches/Parameters:**
  - -Class / -ClassName (specifies WMI/CIM class)
  - -Filter "..." (filters WMI/CIM objects)
  - -Property (limits returned properties)
  - -ComputerName (specifies remote computer)
  - -Credential (specifies credentials for remote access)
- **Examples:**
  ```powershell
  Get-CimInstance Win32_service -Filter "StartMode = 'Auto'" | Select-Object Name, StartMode, PathName
  Get-CimInstance Win32_BIOS | Get-Member
  Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'"
  Get-CimInstance Win32_service -Filter "StartMode = 'Disabled'" | Select-Object Name, StartMode
  Get-CimInstance Win32_OperatingSystem | Select-Object BuildNumber
  Get-CimInstance -ClassName Win32_Process -ComputerName Server64
  Get-CimInstance -ClassName Win32_BIOS | Select-Object -Property SerialNumber
  Get-CimInstance -ClassName Win32_BIOS | Select-Object -Property SerialNumber, Version
  Get-CimInstance Win32_Service -Filter "Name = 'VSS'" -ComputerName RemoteHost,RemoteHost2,RemoteHost3 -Credential $credentials
  Get-CimInstance Win32_OperatingSystem | select-object CSName, Caption | Format-Table -HideTableHeaders | Out-File C:\Users\Trainee\Desktop\hostname-os.txt -Append
  ```

---

## 3. Invoke-Command
- **Switches/Parameters:**
  - -ScriptBlock (provides a script block for remote execution)
  - -ComputerName (specifies remote computer)
  - -Credential (specifies credentials for remote access)
  - -Namespace (specifies WMI namespace)
- **Examples:**
  ```powershell
  Invoke-Command -ScriptBlock {Get-CimInstance Win32_Bios | Select-Object ReleaseDate} -ComputerName 172.16.4.2 -Credential $creds
  Invoke-Command -ComputerName 172.16.4.2 -ScriptBlock {Get-CimInstance -Namespace root\subscription -Class __EventConsumer} -Credential $creds
  Invoke-Command -ComputerName 172.16.4.9 -ScriptBlock {Get-CimInstance -Namespace root\subscription -Class __EventConsumer} -Credential $creds
  Invoke-Command -scriptblock {Get-CimInstance Win32_OperatingSystem | select-object CSName, Caption | Format-Table -HideTableHeaders} -Credential $creds
  ```

---

## 4. Get-Command
- **Switches/Parameters:**
  - -Noun (filters cmdlets by noun)
  - -Module (filters by module)
- **Examples:**
  ```powershell
  Get-Command -Noun WMI*
  Get-Command -Module CimCmdlets
  ```

---

## 5. Import-Module
- **Switches/Parameters:**
  - (Path to module, not shown with -Module)
- **Example:**
  ```powershell
  Import-Module C:\Users\Trainee\Desktop\Lab.ps1
  ```

---

## 6. Get-Content
- **Examples:**
  ```powershell
  Get-Content C:\users\trainee\Desktop\hosts.csv
  ```

---

## 7. Remove-WmiObject
- **Examples:**
  ```powershell
  Get-WmiObject -Query "select * from win32_process where name='notepad.exe'" | Remove-WmiObject
  Get-WMIObject -Query "Select * From Win32_Directory Where Name ='C:\\Test'" | Remove-WmiObject
  ```

---

## 8. Get-Member
- **Examples:**
  ```powershell
  Get-CIMinstance Win32_BIOS | Get-Member
  ```

---

## 9. Select-Object
- **Switches/Parameters:**
  - -Property (limits returned properties)
  - -ExpandProperty (returns only the property value)
- **Examples:**
  ```powershell
  Select-Object Name, StartMode, PathName
  Select-Object -Property SerialNumber
  Select-Object -ExpandProperty message
  ```

---

## 10. Sort-Object
- **Examples:**
  ```powershell
  Sort-Object HandleCount
  ```

---

## 11. Format-Table and Format-List
- **Switches/Parameters:**
  - -HideTableHeaders (Format-Table)
- **Examples:**
  ```powershell
  Format-Table -HideTableHeaders
  Format-List
  ```

---

## 12. Select-String
- **Switches/Parameters:**
  - -Pattern (pattern to search for)
  - -All (matches all occurrences)
- **Examples:**
  ```powershell
  select-string -Pattern '(Account Name:)(.*)' -All
  select-string -Pattern '(Process Name:)(.*)' -All
  ```

---

## 13. Out-File
- **Switches/Parameters:**
  - -Append (appends output to file)
- **Examples:**
  ```powershell
  Out-File C:\Users\Trainee\Desktop\hostname-os.txt -Append
  ```

---

## 14. Get-WinEvent
- **Switches/Parameters:**
  - -MaxEvents (limits number of events)
  - -FilterHashtable (filters events with a hashtable)
- **Examples:**
  ```powershell
  Get-winevent -MaxEvents 200 -filterhashtable @{logname="security";id="4624"}|select-object -expandproperty message
  ```

---

If you need explanations for any command, switch, or example, let me know!
