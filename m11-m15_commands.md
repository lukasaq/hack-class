
System Status Queries
PowerShell offers many cmdlets to query a wide variety of information. These cmdlets are especially useful for obtaining information about the status of a system. The following cmdlets are the most common for retrieving specific system information about local or remote computers: 

Get-WinEvent retrieves Windows event logs from local and remote computers.
Get-Process retrieves the processes running on a local computer.
Get-Service retrieves services on a local computer.
Get-HotFix retrieves the hotfixes installed on a local or remote computer.
The next set of tasks provide hands-on labs to explore each of these cmdlets and their applicable use cases.

Use Get-WinEvent
Get-WinEvent
﻿

The cmdlet Get-WinEvent queries event logs on a local or remote computer. Ideally an environment's logs are gathered and processed by a Security Information and Event Management (SIEM) system. However, analysts may eventually run into a host that is not sending logs off the system. The cmdlet Get-WinEvent provides a convenient on-system option to query system logs, especially when off-system logging is unavailable. This cmdlet also checks the logging configuration of a specified system. 

﻿

Use Get-WinEvent
﻿

Use Get-WinEvent to retrieve the status of log providers on the remote system bp-wkstn-10. Retrieve detailed information and all the available logs from a specific log provider.

﻿

Workflow
﻿

1. Log in to the Virtual Machine (VM) dc01 with the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Open PowerShell as an Administrator.

﻿

3. Return a list of all logging providers for bp-wkstn-10 (whether or not they are enabled) by running the following command:

Get-WinEvent -ComputerName bp-wkstn-10 -ListLog * | Format-Table LogName, IsEnabled
﻿

Adding the flag -ComputerName to this cmdlet enables remote querying.

﻿

4. List more detailed information about a specific log provider by running the following command:

Get-WinEvent -ComputerName bp-wkstn-10 -ListLog Microsoft-Windows-PowerShell/Operational | Format-List -Property *
﻿

5. List all logs from Microsoft-Windows-PowerShell/Operational by running the following command:

Get-WinEvent -ComputerName bp-wkstn-10 -LogName Microsoft-Windows-PowerShell/Operational
﻿

The commands in this lab enable analysts to discover the logging configuration and list logs on a remote system.

﻿

Click "Finish" to exit the event.
Auto-Advance on Correct


Use Get-Process
Get-Process
﻿

The cmdlet Get-Process retrieves information on the processes running on a local host. Running Get-Process on its own returns a list of all active processes on the host. Thereafter, additional commands can be run to drill down into specific processes and discover more information.

﻿

Use Get-Process
﻿

Use Get-Process to retrieve all processes on a local host, as well as detailed information and specific version data on specific processes on the local host. Continue using the VM dc01 to work in PowerShell as an Administrator.

﻿

Workflow﻿

﻿

1. In PowerShell, return the fields Id, Name, and Path for all active processes by running the following command:

Get-Process | Format-Table Id, Name, Path
﻿

2. Return detailed information on the processes conhost and lsass by running the following command:

Get-Process conhost, lsass | Format-List *
﻿

3. Retrieve the version information on the process conhost by running the following command:

Get-Process conhost -FileVersionInfo 2>$null
﻿

The 2>$null part of the command redirects errors to $null, rather than printing them.

﻿

The commands in this lab enable analysts to retrieve useful information about a process running on a local host.

Click "Finish" to exit the event.
Auto-Advance on Correct

Use Get-Service
Get-Service
﻿

The cmdlet Get-Service retrieves information on the services running on a local host. Running Get-Service on its own returns a list of all services on the host.

﻿

Use Get-Service
﻿

Use Get-Service to retrieve all running services on a local host, all running services that contain a specific string, and additional details on a specific service running on the local host. Continue using the VM dc01 to work in PowerShell as an Administrator.

﻿

Workflow
﻿

1. In PowerShell, list all running services by entering the following command:

Get-Service | Where-Object {$_.Status -eq "Running"}
﻿

2. Display all running services that have names starting with net by running the following command:

Get-Service -Name "net*" | Where-Object {$_.Status -eq "Running"}
﻿

3. Return additional details about the service Netlogon by running the following command:

Get-Service -Name Netlogon | Format-List *
﻿

The commands in this lab enable analysts to retrieve information on services running on a local host. 

﻿

Click "Finish" to exit the event.
Auto-Advance on Correct

Use Get-HotFix
Get-HotFix
﻿

The cmdlet Get-HotFix queries installed hotfixes on a local or remote computer. This is useful when auditing a group of systems to ensure important hotfixes have been applied. Running Get-HotFix by itself lists all hotfixes on the local machine. 

﻿

Use Get-HotFix
﻿

Use Get-HotFix to retrieve all installed hotfixes on a remote host, hotfixes containing a specific string, and a hotfix with a specific hotfix Identifier (ID). Continue using the VM dc01 to work in PowerShell as an Administrator.

﻿

Workflow
﻿

1. In PowerShell, return all hotfixes installed on bp-wkstn-9 by running the following command:

Get-HotFix -ComputerName bp-wkstn-9
﻿

2. Display security update hotfixes, sorted by the date installed, by running the following command:

Get-HotFix -Description Security* -ComputerName bp-wkstn-9 | Sort-Object -Property InstalledOn
﻿

3. Return detailed information on a specific hotfix run by running the following command:

Get-HotFix -Id KB2847927 -ComputerName bp-wkstn-9 | Format-List *
﻿

The commands in this lab enable analysts to query installed hotfixes on a remote computer.

Click "Finish" to exit the event.
Auto-Advance on Correct

Summary of System Status Queries
The cmdlets covered in the previous series of task cards only scratch the surface of PowerShell's capabilities. There is much more to learn, to be able to use PowerShell effectively as a defense analyst. Review the additional resources listed below to find out more about the cmdlets discussed in the section.

﻿

Additional Resources
PowerShell Module Browser: https://docs.microsoft.com/en-us/powershell/module/?view=powershell-7.1
Get-WinEvent: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.2
Get-Process: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-process?view=powershell-7.2
Get-Service: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-service?view=powershell-7.2
Get-HotFix: htt ps://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-hotfix?view=powershell-7.2
 ﻿
﻿

Click "Finish" to exit the event.


Query Installed HotFixes
Use the knowledge and skills from the previous tasks to complete the following challenge.

﻿

Query Installed HotFixes
﻿

Audit installed HotFixes on the systems bp-wkstn-9 and bp-wkstn-10.

﻿

Workflow
﻿

1. Log in to the VM dc01 using the following credentials: 

Username: trainee
Password: CyberTraining1!
﻿

2. Use administrative PowerShell to identify answers for the next set of questions.

﻿

For assistance, refer to the manual page for Get-HotFix using the following command:

Get-Help Get-HotFix 




Additional Resources
Get-HotFix: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-hotfix?view=powershell-7.2
﻿

Click "Finish" to exit the event.

System Settings Queries
Using PowerShell to query and set system settings increases the efficiency of many tasks. Instead of clicking through a graphical user interface, PowerShell uses elegant commands that quickly perform almost any task imaginable on Windows systems. The next set of task cards introduces the following types of cmdlets:

Group Policy Object (GPO)
Item
NetFirewallRule
To explore additional modules and cmdlets on the system, use the cmdlets Get-Module and Get-Command.

Use GPO Cmdlets
GPO Cmdlets
﻿

The GPO cmdlets are part of the module GroupPolicy. These cmdlets administer Group Policy in a Windows Server.

﻿

Use GPO Cmdlets
﻿

Use GPO cmdlets to retrieve information on GPO policies in a domain, create a new GPO policy, and export a report about the newly created GPO policy.

﻿

Workflow
﻿

1. Log in to the VM dc01 using the following credentials: 

Username: trainee
Password: CyberTraining1!
﻿

2. Using an administrative PowerShell, return all GPOs on the domain energy.lan by running the following command:

Get-GPO -All -Domain "energy.lan"
﻿

3. Create a new GPO in the domain of the user with the cmdlet New-GPO, as follows:

New-GPO -Name "ScreenSaverTimeout" -Comment "This sets the screen saver timeout to 5min."
﻿

4. Apply a registry-based policy to the new GPO by running the following command:

Set-GPRegistryValue -Name "ScreenSaverTimeout" -Key "HKCU\Software\Policies\Microsoft\Windows\Control Panel\Desktop" -ValueName ScreenSaveTimeOut -Type String -Value 300
﻿

5. Link the GPO to an Organizational Unit (OU) by running the cmdlet New-GPLink, as follows:

New-GPLink -Name "ScreenSaverTimeout" -Target "ou=bp,dc=energy,dc=lan"
﻿

6. Save a HyperText Markup Language (HTML) report of the new GPO to the desktop by running the cmdlet Get-GPOReport, as follows:

Get-GPOReport -Name "ScreenSaverTimeout" -ReportType HTML -Path "C:\Users\trainee\Desktop\gporeport.html"
﻿

7. Open and review the newly generated report.

﻿

The commands in this lab enable analysts to query information on and create Group Policy objects. The GPO report generated in the last step displays information about a GPO that can be shared with the team. The information is identical to what is presented in the Group Policy editor in Windows. 


Use Item Cmdlets
Item Cmdlets
﻿

The item cmdlets are part of the module Microsoft.PowerShell.Management. These cmdlets query and set items in different types of data stores. For example, item cmdlets may be used to query and modify registry keys.

﻿

Use Item Cmdlets
﻿

Use Item cmdlets to retrieve information on a registry key, create a new registry entry, and remove a registry key. Continue using the VM dc01 to work in PowerShell as an Administrator.

﻿

Workflow
﻿

1. In PowerShell, query a run key in the local machines registry by entering the following command:

Get-Item HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
﻿

2. Create a new property in the run key with the cmdlet New-ItemProperty, as follows: 

New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Notepad" -Value "%windir%\system32\notepad.exe"
﻿

The cmdlet New-Item is also available to create a whole new registry key.

﻿

3. Display the new property by running the cmdlet Get-Item, as follows:

Get-Item HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
﻿

4. Delete the property by running the cmdlet Remove-ItemProperty, as follows:

Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Notepad"
﻿

The commands in this lab enable analysts to query the  registry and manage registry e ntries on a local host.

﻿
Use NetFirewallRule Cmdlets
NetFirewallRule Cmdlets
﻿

The NetFirewallRule cmdlets are part of the module NetSecurity and are used to modify host firewall rules.

﻿

Use NetFirewallRule Cmdlets
﻿

Use NetFirewallRule cmdlets to retrieve a local host's firewall profiles, retrieve information on a local host's firewall rules, create a new firewall rule on the local host, and disable a firewall rule on a local host. Continue using the VM dc01 to work in PowerShell as an Administrator.

﻿

Workflow
﻿

1. In PowerShell, list all the firewall profiles on the local host by running the following command:

Get-NetFirewallProfile -All
﻿

2. List all the rules in the profile domain by entering the cmdlet Get-NetFirewallRule, as follows:

Get-NetFirewallProfile -Name Domain | Get-NetFirewallRule
﻿

3. Create a new firewall rule in the domain profile to block all outbound traffic to port 1337 by running the cmdlet New-NetFirewallRule, as follows:

New-NetFirewallRule -DisplayName "Block Outbound Port 1337" -Direction Outbound -LocalPort 1337 -Protocol TCP -Action Block -Profile Domain
﻿

4. Review the new rule using the cmdlet Get-NetFirewallRule, as follows:

Get-NetFirewallRule -DisplayName "Block Outbound Port 1337"
﻿

5. Disable the new rule with the cmdlet Disable-NetFirewallRule, as follows:

Disable-NetFirewallRule -DisplayName "Block Outbound Port 1337"
﻿

6. Verify the rule was disabled by viewing the information output by the following command:

Get-NetFirewallRule -DisplayName "Block Outbound Port 1337"
﻿

If Enabled is set to False, this indicates that the rule is successfully disabled. This last step and the previous commands presented in this lab enable analysts to interact with a local host firewall and manage its rules.





















