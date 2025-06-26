#### CDAH-M11L1-PowerShell Fundamentals Review ####


To list all possible cmdlets in a system, the cmdlet Get-Command is extremely helpful. 
Get-Command -Type Cmdlet



For example, executing the Get-Member cmdlet on any directory object, such as a user’s Documents folder, returns the following output.
PS C:\Users\trainee> Get-Item ".\Documents\" | Get-Member

This cmdlet is used to retrieve a list of all scheduled tasks in the system. These are often a vector for adversary persistence or may be disabled by adversaries when the task runs scripts or programs to search for malicious activity. 

Get-ScheduledTask 

Get-ScheduledTask -TaskName Proxy | Format-List *


Get-Process | Where-Object {($_.ProcessName -like "*host*") -and ($_.CPU -lt 5) -and ($_.CPU -gt 0.01)


Select-String -Path "C:\path\to\file" -Pattern "pattern"



Get-Process | Where-Object -Property Name -match "explorer" | Format-Table Name, Description, Path, ID


Get-ScheduledTask | Where-Object {
    ($_ | Get-ScheduledTaskInfo).NextRunTime -like "7:00:00 AM"
}


#### CDAH-M11L2-Querying Active Directory with PowerShell ####

To effectively prevent this vulnerability, analysts may write a query that filters for accounts configured with the flag DONT_EXPIRE_PASSWORD set. In the AD user object, this flag is designated by the field passwordNeverExpires. The following query fulfills these requirements:
Get-ADUser -filter { passwordNeverExpires -eq $true -and enabled -eq $true } | Select Name, DistinguishedName


Invoke-Command -Session $session -ScriptBlock {Get-ADUser -filter * -properties DoesNotRequirePreAuth | where {$_.DoesNotRequirePreAuth -eq "TRUE"} | select samaccountname}

Get-ADUser -filter * -properties DoesNotRequirePreAuth | where {$_.DoesNotRequirePreAuth -eq "TRUE"} | select samaccountname

#### CDAH-M11L3-Cmdlet Use and Development ####


#### CDAH-M11L5-PowerShell System Administration ####

In PowerShell, list all running services by entering the following command:
Get-Service | Where-Object {$_.Status -eq "Running"}

### CDAH 25-080 M12L2Exploiting PowerShell Autoruns ###

It looks like you're asking about the `Find-MissingLibraries` command, but just to clarify—there isn’t a widely known or standard command by that exact name in common operating systems like Windows, Linux, or macOS. However, if you're referring to a script or tool (possibly PowerShell or a Linux utility) designed to detect missing shared libraries or dependencies, I can definitely help you explore that.

If you're working in **Linux**, the typical way to find missing libraries for executables is using tools like:

- `ldd <executable>` — lists shared object dependencies
- `ldd <executable> | grep "not found"` — shows missing ones
- `strace` — traces system calls and can help identify missing files
- `ldconfig` — updates the shared library cache

If you're in **PowerShell**, and `Find-MissingLibraries` is a custom or community module, the syntax might look like:

```powershell
Find-MissingLibraries -Path "C:\Path\To\Executable" -Verbose
```

Common switches might include:
- `-Path` — specifies the file or directory to scan
- `-Recurse` — scans subdirectories
- `-Verbose` — outputs detailed information
- `-LogFile` — saves results to a file

If you can tell me the environment you're working in (Linux, Windows, macOS) or the specific tool or script you're referring to, I can tailor the examples and options more precisely. Want to dig into a specific use case?

### CDAH 25-080 M12L3 Build a PowerShell Launcher 

Manipulating Base64 Strings


The following PowerShell code demonstrates the process for taking a string and converting it to the base64 equivalent, followed by the function to decode the base64 back into a plaintext string.
#Convert to a base64 string
$Text = 'get-process'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)

#$Encoded Text is: ZwBlAHQALQBwAHIAbwBjAGUAcwBzAA==

#Decode
$DecodedText = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedText))

---

### CDAH-M12L4-Using PowerShell to Grab WMI Objects 

PS C:\>Get-WmiObject -List

![image](https://github.com/user-attachments/assets/aa62713d-0624-49c5-97bd-a6530ff4460f)

get-win32_service


The following command finds and lists all services that start at the time the computer boots. It uses the class Win32_Service, as well as the option -Filter and the cmdlet Select-Object:
PS C:\>Get-CimInstance Win32_service -Filter "StartMode = 'Auto'"|Select-Object Name, StartMode, PathName

 common task such as retrieving running processes on a remote server, can be accomplished by running the following command:
PS C:\> Get-CimInstance -ClassName Win32_Process -ComputerName Server64

Close the Running Process notepad.exe
Get-WmiObject -Query "select * from win32_process where name='notepad.exe'" 
| Remove-WmiObject



Delete the Folder Test
Get-WMIObject -Query "Select * From Win32_Directory Where Name ='C:\\Test'" 
| Remove-WMIObject

![image](https://github.com/user-attachments/assets/8150bf1b-0a80-4366-98b4-8a68afc143dc)

![image](https://github.com/user-attachments/assets/95d29717-0a8f-48d3-900f-f41c80707d67)


----------------
 ### CDAH-M13L1-Python Data Types and Program Flow ###





------------------------

### CDAH-M13L2-Python Data Structures ###





















