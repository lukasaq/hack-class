Certainly! Here’s a fully detailed, copy-paste-friendly guide to every PowerShell command found in the referenced file, including syntax examples, common parameters/switches, and practical explanations. This is formatted for easy reading, reference, and direct use.

---

# PowerShell Command Reference from `m11-m15.md`

---

## **1. Object Creation & Data Structures**

### **Custom Object**
```powershell
$newObject = [PSCustomObject]@{
    Property1 = $output.property1
    Property2 = $secondoutput.property2
}
```
- **Description**: Creates a custom object with named properties and values.

### **Hash Table**
```powershell
$newHashTable = @{ key1 = $value1; key2 = "value2"; key3 = 3 }
```
- **Description**: Creates a hash table (key-value store).

**Add or set values:**
```powershell
$hashTable = @{}
$hashTable.Foo = 'Bar'
$hashTable['Foo'] = 'Bar'
$hashTable.Add('Foo', 'Bar')
```

---

## **2. Function Definition & Parameters**

### **Basic Function**
```powershell
function Custom-Function {
    Write-Output "Hello World"
}
```

### **Function with Parameters**
```powershell
function Example {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]$Variable
    )
}
```
**Call the function:**
```powershell
Example -Variable "DATA"
```

### **Pipeline Input**
```powershell
function PipeExample {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [string]$Variable
    )
    process {
        Write-Output $Variable
    }
}
@("DATA1", "DATA2", "DATA3") | PipeExample
```

### **Dynamic Parameters**
```powershell
dynamicparam {
    if ($Condition) {
        # code
    }
}
```

### **Begin/Process/End Blocks**
```powershell
function Example {
    begin { # Initialization, runs once }
    process { # Runs for each piped object }
    end { # Cleanup, runs once after all objects }
}
```

---

## **3. Cmdlets, Modules, and Aliases**

### **Listing Cmdlets**
```powershell
Get-Command -Type Cmdlet
```

### **Importing a Module**
```powershell
Import-Module <Module-Name>
```

### **View Members of an Object**
```powershell
Get-Item ".\Documents\" | Get-Member
```

### **View Aliases**
```powershell
Get-Alias    # or shorthand:
gal
```

---

## **4. Data Gathering Cmdlets**

### **Get-Item**
```powershell
Get-Item -Path <Path>
Get-Item HKLM:\Software\Microsoft\Powershell\1\Shellids\Microsoft.Powershell\
Get-Item -Path "C:\*"
```
- **Parameters**:  
  - `-Path <string>`

### **Get-ItemProperty**
```powershell
Get-ItemProperty -Path <RegistryPath>
Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\
```

### **Get-ChildItem** (dir, ls, gci)
```powershell
Get-ChildItem -Path "C:\"
Get-ChildItem -Path "C:\Users\*\Downloads"
Get-ChildItem -Recurse -Include *.exe
```
- **Parameters**:  
  - `-Path <string>`
  - `-Recurse`
  - `-Include <string[]>`

### **Get-Content**
```powershell
Get-Content -Path "C:\path\to\file"
Get-Content -Path "C:\path\to\file" -Stream <StreamName>
```
- **Parameters**:  
  - `-Path <string>`
  - `-Stream <string>`

### **Get-Process** (alias: gps)
```powershell
Get-Process
Get-Process -ProcessName "explorer" | Format-List *
```
- **Parameters**:  
  - `-ProcessName <string>`

### **Get-CimInstance** (replacement for Get-WmiObject)
```powershell
Get-CimInstance -ClassName Win32_Product
Get-CimInstance -ClassName Win32_Process
Get-CimInstance -ClassName Win32_ComputerSystem
Get-CimInstance -ClassName <ClassName> -Filter @{"property"=VALUE} -Property Name
Get-CimInstance -Query "<WQL query>"
```
- **Parameters**:
  - `-ClassName <string>`
  - `-Filter <hashtable>`
  - `-Property <string[]>`
  - `-Query <string>`

### **Get-Service**
```powershell
Get-Service
Get-Service -DisplayName "DNS Client" | Format-List *
```
- **Parameters**:
  - `-DisplayName <string>`

### **Get-NetTCPConnection**
```powershell
Get-NetTCPConnection
Get-NetTCPConnection -LocalPort 139 | Format-List *
```
- **Parameters**:
  - `-LocalPort <int>`

### **Get-ScheduledTask**
```powershell
Get-ScheduledTask
Get-ScheduledTask -TaskName Proxy | Format-List *
```
- **Parameters**:
  - `-TaskName <string>`

---

## **5. Data Manipulation Cmdlets**

### **Select-Object** (alias: select)
```powershell
Select-Object -Property Property1, Property2
Get-Process | Select-Object Name, ID, Description
Get-Process | Where-Object Name -eq explorer | Select-Object -ExpandProperty Modules
```
- **Parameters**:
  - `-Property <string[]>`
  - `-ExpandProperty <string>`

### **Where-Object** (alias: where)
```powershell
Where-Object { $_.Property -eq 'Value' }
Get-Process | Where-Object {($_.ProcessName -like "*host*") -and ($_.CPU -lt 5) -and ($_.CPU -gt 0.01)}
```
**Supported comparison operators:**
- `-contains`, `-notcontains`, `-in`, `-notin`
- `-like`, `-notlike`, `-match`, `-notmatch`
- `-eq`, `-ne`, `-gt`, `-ge`, `-lt`, `-le`

### **Select-String**
```powershell
Select-String -Path "C:\path\to\file" -Pattern "pattern"
<Data-Object> | Select-String -Pattern "pattern"
<Data-Object> | Select-String -InputObject ($_.Property) -Pattern "pattern"
```
- **Parameters**:
  - `-Path <string>`
  - `-Pattern <string>`
  - `-InputObject <object>`

### **Format-List** (alias: fl)
```powershell
Format-List -Property Property1, Property2
Get-Process | Where-Object Name -match "explorer" | Format-List Name, Description, Path, ID
```
- **Parameters**:
  - `-Property <string[]>`

### **Format-Table** (alias: ft)
```powershell
Format-Table -Property Property1, Property2
Format-Table -AutoSize
Format-Table -Wrap
Get-Process | Where-Object Name -match "explorer" | Format-Table Name, Description, Path, ID
```
- **Parameters**:
  - `-Property <string[]>`
  - `-AutoSize`
  - `-Wrap`

### **Sort-Object**
```powershell
Sort-Object -Property PropertyName -Descending
Get-Process | Sort-Object -Property WS -Descending
```
- **Parameters**:
  - `-Property <string>`
  - `-Descending`
  - `-Ascending`
  - `-Unique`

### **ForEach-Object** (alias: foreach, %)
```powershell
<Data-Object> | ForEach-Object -Begin {commands} -Process {command1; command2} -End {commands}
Foreach ($object in $collection) {
    Example-Cmdlet -Input $object
}
```
- **Parameters**:
  - `-Begin <scriptblock>`
  - `-Process <scriptblock>`
  - `-End <scriptblock>`

---

## **6. Input and Output Cmdlets**

### **Invoke-Command**
```powershell
Invoke-Command -ComputerName TEST001 -Credential Domain\User -ScriptBlock {Command1; Command2}
Invoke-Command -Session $sessionName -ScriptBlock {Command1; Command2}
```
- **Parameters**:
  - `-ComputerName <string>`
  - `-Credential <pscredential>`
  - `-ScriptBlock <scriptblock>`
  - `-Session <PSSession>`

### **Write-Output**
```powershell
Write-Output "The time and date is $(Get-Date)"
```

### **Out-File**
```powershell
<Data> | Out-File -Path "C:\path\to\out\file" -Append
```
- **Parameters**:
  - `-Path <string>`
  - `-Append`

---

## **7. Common Cmdlet Parameters (Switches)**

### **ErrorAction**
- **Usage**: Controls what happens if a cmdlet encounters an error.
```powershell
-ErrorAction Stop
-ErrorAction Continue
-ErrorAction SilentlyContinue
-ErrorAction Ignore
-ErrorAction Inquire
```

### **Force**
- **Usage**: Overrides restrictions, useful for deleting hidden files, etc.
```powershell
-Force
```

---

## **8. Active Directory Cmdlets**

### **Get-ADDomain**
```powershell
Get-ADDomain
```

### **Get-ADForest**
```powershell
Get-ADForest
```

### **Get-ADOrganizationalUnit**
```powershell
Get-ADOrganizationalUnit -Filter *
```
- **Parameter**:  
  - `-Filter <string>`

### **Get-ADGroup**
```powershell
Get-ADGroup -Filter *
Get-ADGroup -Identity Administrators -Properties *
```
- **Parameters**:
  - `-Filter <string>`
  - `-Identity <string>`
  - `-Properties <string[]>`

### **Get-ADGroupMember**
```powershell
Get-ADGroupMember -Identity Administrators
```
- **Parameter**:
  - `-Identity <string>`

---

## **9. Example Situational Awareness Script Commands**

```powershell
Get-Process
Get-Service
Get-ScheduledTask
Get-NetTCPConnection
Get-CimInstance -ClassName Win32_Product
Get-ChildItem -Path C:\Users\*\Downloads
Get-ChildItem -Path C:\Users\AppData\Local\Temp
Get-ChildItem -Path C:\ProgramFiles
Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
Get-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServices"
Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce"
Get-Item "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce\Setup"
```

---

### **If you want a deeper example or a breakdown of a specific command, let me know!**
