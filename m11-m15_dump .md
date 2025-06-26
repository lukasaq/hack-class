What Are PowerShell Profiles?


PowerShell profiles are scripts that load regularly-used elements in a Windows PowerShell ISE session. PowerShell has two "modes": the console and the ISE. The PowerShell console is the standard shell that many systems administrators use to perform simple tasks such as user management, system updates, and any other one-off PowerShell commands that need to be run. The ISE is used for scripting more complex tasks such as applying all the configuration changes necessary to make a fresh install of Windows compliant with specific government standards. Any changes required in the configuration script are implemented in the ISE. Users add any necessary environmental elements to their profiles. An example of a profile element is an array of registry keys that a user may need to change.


For defense purposes, profiles provide one of the most powerful system tools for threat hunting. In an example scenario, cybersecurity researchers may maintain a list of Advanced Persistent Threat (APT) actors and regularly update a publicly available website with new Indicators of Compromise (IoC). In this case, a defender could create a PowerShell script that downloads the relevant data from the IoC site and adds it to an array in the current session. That script could then be added to the PowerShell profile. This way, every time that the defender loads a new PowerShell session, the script downloads the most recent APT-related data to use.




PowerShell Object Persistence
PowerShell objects are similar to objects in object-oriented programming. In the context of security defense, objects act as containers that store different kinds of information about other elements in the operating system. For example, the object ServiceController manages any given service on a host. This object has cmdlets such as Start-Service, Stop-Service, Set-Service, and get-Service. The PowerShell commands related to this object manage various application and system services on a host.

﻿

Defenders commonly gather information from a specific object for examination during a hunt, also known as baselining. In an example scenario, an exploit might alter a system service in a way that is not logged by normal logging methods. An analyst might then need to export the status of the service under specific conditions to verify potential compromise. The analyst would then baseline by creating a persistent snapshot of the service object to use for later analysis. The third-party PowerShell modules like "DeepBlueCLI" export a saved snapshot of the object in several different formats for analysis. The other method of creating a baseline with a persistent object is to create a script that grabs the object information at startup in the PowerShell profile. For example, analysts could create a script that always checks system resource usage when a PowerShell profile is loaded to verify that their current host is behaving as intended. This script would act as the baseline for the defenders.﻿

﻿

Persistent Object Exploitation
﻿

Adversaries often attempt to hijack an administrator's session to gain persistence within the administrator's PowerShell profile. One example of a session hijack exploit is an attack that was used in tandem with the Common Vulnerabilities and Exposures (CVE) CVE-2021-40444, wherein a malicious Dynamic-Link Library (DLL) file is deposited into the directory /tmp/. A path traversal vulnerability was exploited to add malicious code into the PowerShell profiles that the current active user has access to. The attack utilizes MITRE ATT&CK code T1546.013, Event Triggered Execution: PowerShell Profile, which illustrates this as an event triggered execution technique.

﻿

Many PowerShell profile exploits require another type of compromise, such as phishing, to attack PowerShell directly. However, profile compromise is one example as to why defenders should encourage their organization to focus on local vulnerabilities that adversaries will seek to exploit post-compromise.

﻿

PowerShell objects are another vector for potential compromise that defenders must be vigilant about. Exploiting objects is one example of a fileless malware attack, since objects are not explicit files. Rather, objects are containers for other system functions. Adversaries use exploits, such as a compromised website, to open a silent PowerShell session, inject encrypted scripts, and stealthily “live off of the land” without putting an actual file on the compromised target. An adversary could use this fileless malware technique to inject their malicious code into the object, so that when the object is called and logged, it appears as normal administrative tasks. This would be the attack T1546.015, Event Triggered Execution: Component Object Model Hijacking.

﻿

Examining PowerShell objects requires hybrid analysis, which is an advanced technique that will be covered in a later module.


Compromise a PowerShell Profile


Use PowerShell to add a compromised script to a profile to hijack a session each time it is launched.


Workflow


1. Log into the Virtual Machine (VM) win-hunt with the following credentials:
Username: trainee
Password: CyberTraining1!



2. Launch PowerShell as an administrator.


3. Enable the use of scripts within PowerShell by entering the following command:
PS C:\Windows\system32> Set-ExecutionPolicy Bypass -Scope CurrentUser -Force



4. Create a fresh PowerShell profile with the following command since a powershell does not have one configured by default:
PS C:\Windows\system32> New-Item -Path $PROFILE -type File -force



This command creates a new Current User, Current Host profile with default settings in the user's documents folder, as displayed in Figure 12.2-1, below:





Figure 12.2-1


5. Open the profile as a text file to edit it by entering the following command:
PS C:\Windows\system32> start C:\Users\trainee\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1



6. Add the following text in the new profile window to launch a simple function each time the profile is loaded:
Get-Service | Get-Member



The function Get-Member lists the properties and methods of the cmdlet Get-Service.
 
7. Save and exit the profile file.


8. Reopen PowerShell. 


The list of options for the Get-Service object is now displayed as part of the profile file, as indicated in Figure 12.2-2, below:





Figure 12.2-2


9. To conduct an attack, overwrite the current profile with a premade compromised profile by entering the following command:
PS C:\Windows\system32> Copy-Item C:\Users\trainee\Documents\Microsoft.PowerShell_profile.ps1 C:\Users\trainee\Documents\WindowsPowerShell\ -Force



This overwrites the default user profile with a malicious profile from the specified file location.


10. Exit PowerShell and reopen it to view the compromised profile. 


A document pops up as an example of an object being loaded that the user did not configure.


11. Exit the document window that the compromised profile opened.


12. Reset the profile to clear the compromised command with the following command:
PS C:\Windows\system32> Clear-Content C:\Users\trainee\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1



13. Exit and reopen PowerShell to verify that the profile has been cleared.


Workflow


1. Log into the VM win-hunt with the following credentials:
Username: trainee
Password: CyberTraining1!



2. Open PowerShell as an administrator.


3. Import the module acCOMplice into this session with the following command:
PS C:\Windows\system32> Import-Module C:\Users\trainee\Documents\acCOMplice\COMHijackToolkit.ps1



4. Find all registry keys that have symbolic links to files that do not exist by entering the following command:
PS C:\Windows\system32> Find-MissingLibraries





Figure 12.2-3, below, displays the expected output from step 4:





Figure 12.2-3


If an adversary was able to enumerate these keys, they could create malicious files with the found DLL names. The relevant registry keys would execute those malicious DLLs after running the relevant application's code. An adversary could then hide within an installed application using a file that is expected to exist. 


Use the information from this workflow to answer the next question.



































































