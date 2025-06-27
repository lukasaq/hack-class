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





## CDAH-M13L3-Python Functions and Classes

Class Layout and Characteristics
The previous Python code examples in this lesson used variables and methods to manipulate data and program output. Another valuable tool is the Python class, which can be thought of as a mold for creating objects. Just as a mold shapes various types of materials, a single Python class can create various objects that share common attributes. 

﻿

The following lines of code illustrate the usefulness of Python classes. The first line defines the class without using the keyword def. This is followed by an object constructor __init__, which initializes a newly created object state. Since this Python class is concerned with malware, assume that each object of this class is a certain kind of malware (virus, trojan, worm, etc.) and the instance variables help define the object in relation to the class.

﻿

class Malware:

  # Constructor
  def __init__(self,name,mtype,tlevel)

    # Instance variables
    self.name = name
    self.mtype = mtype
    self.tlevel = tlevel

  # Class attributes
  attr1 = "has a malware signature"
  attr2 = "has been analyzed"

  # Class method
  def define(self):
    print(self.name, self.attr1)
    print(self.name, self.attr2)
    print("Refer to documentation for", self.name)
﻿

The instance variables are name, mtype (malware type), and tlevel (threat level). These instance variables have values provided as attributes to the constructor when a class object is instantiated, such as with the following line of code:

malware1 = Malware("Cryptolocker","trojan","high")
﻿

Instantiating an object in Python is similar to calling a method. The difference is that a class creates an object and assigns attributes to that object, while a method simply performs some action. In addition to instance variables that are specific to certain objects, there are also class attributes that are shared by each object of a class. In the example above, each object that is a member of the class Malware shares two attributes, regardless of the values of the instance variables.

﻿

Finally, classes may also contain their own methods. Defining a method within a class benefits from the parameter self, which is a reference to a particular object instance. For example, malwa re1 in th e code above is a variab le which  holds a Malware class object with the name Cryptolocker . The me thod define within the class Malware only needs to take in the parameter self, rather than a specific name value. This is because the name Cryptolocker is passed as an instance variable specific to the object malware1 and is referenceable as self.name when used in the class  method.















