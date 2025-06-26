What Is WMI/CIM?
CIM and WMI are used interchangeably to refer to the infrastructure for managing data and operations on Windows-based operating systems. CIM is an open standard from the Distributed Management Task Force (DMTF). CIM provides a common definition of management information for systems, networks, applications, and services. CIM allows for vendor extensions. WMI is Microsoft’s proprietary implementation of CIM for the Windows platform. CIM and WMI share the same purpose, as well as many equivalent functions and features.

﻿

WMI and CIM are commonly misunderstood as a single tool or command. Rather, WMI and CIM form a framework for accessing data stored within classes. An example of a class is Win32_Process, which contains the running processes of a Windows host. CIM_Process is the CIM version of Win32_Process.

﻿

Commands and Classes
﻿

There are two main commands for accessing WMI: Get-WmiObject and Get-CimInstance. The command Get-WmiObject is the precursor to Get-CimInstance and is now the deprecated method for accessing WMI. Although Get-WmiObject still functions, Microsoft recommends using the command Get-CimInstance when using PowerShell 3.0 and above. Both Get-WmiObject and Get-CimInstance use the same or equivalent class names, but have other differences outlined in this lesson.

﻿

The command Get-WmiObject has an alias that shortens the command to gwmi. The alias for Get-CimInstance is gcim. This lesson uses both WMI and CIM aliases to interact with the classes within WMI. 

﻿

There are at least 137 classes available within WMI, which can be difficult to remember. Running the following command in PowerShell provides a complete, verbose list of Windows classes to query:

PS C:\>Get-WmiObject -List
﻿

Below, Table 12.4-1 provides three useful classes from the complete list that pertains to network defenders:

﻿
Querying WMI for Investigations
The different classes in WMI contain useful information about the activity and behavior of a Windows host. Recognizing the most common classes enables a defender to quickly access important information from the host to use during investigations. The two ways that WMI can be used are locally and remotely. 

﻿

The command Get-Member can be used with Get-CIMinstance to display all available fields of a specific class. This command combination prints a table that contains the Name, MemberType and Definition of the available fields that can be filtered on. The following syntax retrieves this table for the class Win32_BIOS, which can be replaced with any other class to display its corresponding information:

Get-CIMinstance Win32_BIOS | Get-Member
﻿

Local Machines
﻿

One example of using the WMI command for a local machine is to query the host to examine which services are configured. This is particularly useful for investigating a host that potentially has a malicious service. 

﻿

The following command finds and lists all services that start at the time the computer boots. It uses the class Win32_Service, as well as the option -Filter and the cmdlet Select-Object:

PS C:\>Get-CimInstance Win32_service -Filter "StartMode = 'Auto'"|Select-Object Name, StartMode, PathName
﻿

The option -Filter limits the results to only return services that automatically start at boot, as noted by "StartMode = 'Auto'". The pipe to the cmdlet Select-Object filters the objects returned to only display the Name, StartMode, and PathName.

﻿

Remote Machines
﻿

Both Get-WmiObject and Get-CimInstance can be used to access remote machines. However, this depends on the services the remote system supports and has running. Get-WmiObject uses Distributed Component Object Model (DCOM) and Get-CimInstance uses Windows Remote Management (WinRM).

﻿

For remote access to work, the Windows Firewall must be configured to allow DCOM and WinRM traffic. For example, DCOM operates on port 135, which is open by default on all Windows systems. Therefore, Get-WmiObject is often easier to use. WinRM, on the other-hand, listens on both Hypertext Transfer Protocol (HTTP) port 5985 and Hypertext Transfer Protocol Secure (HTTPS) on port 5986. These are enabled by default on servers and are typically disabled on workstations for Get-CimInstance.

﻿

The commands Get-WmiObject and Get-CimInstance allow defenders to search for Indicators of Compromise (IOC) across a large number of hosts. Any command that can be run locally can also be run remotely. A common task such as retrieving running processes on a remote server, can be accomplished by running the following command:

PS C:\> Get-CimInstance -ClassName Win32_Process -ComputerName Server64
﻿

In this command, the field -ComputerName needs to be populated with the name of a computer or an IP address to be able to access the remote host.
PowerShell Commands to Query WMI
Run PowerShell Commands to Query WMI
﻿

This lesson introduced three common WMI classes and why they would be of use. Run each of the commands in the following workflow to review their output and answer the questions that follow.

﻿

Workflow
﻿

1. Log in to the Virtual Machine (VM) win-hunt using the following credentials: 

Username: trainee
Password: CyberTraining1!
﻿

2. Open PowerShell as an Administrator.

﻿

3. In the PowerShell Terminal, enter the following command to display a filtered output of Win32_Process that only displays information relating to powershell.exe:

PS C:\Windows\System32> Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'"
﻿

Answer the question on the next task, then continue with the next steps of this workflow, presented thereafter.

﻿PowerShell Commands to Query WMI
Run PowerShell Commands to Query WMI
﻿

This lesson introduced three common WMI classes and why they would be of use. Run each of the commands in the following workflow to review their output and answer the questions that follow.

﻿

Workflow
﻿

1. Log in to the Virtual Machine (VM) win-hunt using the following credentials: 

Username: trainee
Password: CyberTraining1!
﻿

2. Open PowerShell as an Administrator.

﻿

3. In the PowerShell Terminal, enter the following command to display a filtered output of Win32_Process that only displays information relating to powershell.exe:

PS C:\Windows\System32> Get-CimInstance Win32_Process -Filter "Name = 'powershell.exe'"
﻿

Answer the question on the next task, then continue with the next steps of this workflow, presented thereafter.

﻿Query WMI to Discover Disabled Services
Query WMI to Discover Disabled Services
﻿

Workflow
Run the following command. Use the output to answer the question that follows.

﻿

1. In the PowerShell Terminal, in the VM win-hunt, enter the following:

PS C:\Windows\System32> Get-CimInstance Win32_service -Filter "StartMode = 'Disabled'"|Select-Object Name, StartMode
﻿Query WMI for Remote Host Information
Query WMI to Obtain BIOS Information from a Remote Host
﻿

Workflow
﻿

Run the following command. Use the output to answer the question that follows.

﻿

1. In the PowerShell Terminal, in the VM win-hunt, enter the following:

PS C:\Windows\System32> Import-Module C:\Users\Trainee\Desktop\Lab.ps1
﻿

2. Enter the following:

PS C:\Windows\System32> Invoke-Command -ScriptBlock {Get-CimInstance Win32_Bios |Select-Object ReleaseDate} -ComputerName 172.16.4.2 -Credential $creds
﻿
Query WMI for Local Machine Information
Query WMI to Obtain Information About a Local Machine
﻿

Workflow
﻿

Run the following command. Use the output to answer the question that follows.

﻿

1. In the PowerShell Terminal, in the VM win-hunt, enter the following:

PS C:\Windows\System32> Get-CimInstance Win32_OperatingSystem|Select-Object BuildNumber
﻿
Comparison of WMI Querying Methods
WMI Query Language (WQL)
﻿

In previous sections it was demonstrated that WMI information can be accessed through Get-WmiObject and Get-CimInstance. WQL is another option for accessing WMI information. WQL allows for the same type of queries as the previous two commands, but uses Structured Query Language (SQL) formatting. 

﻿

The main WQL statements are Select, Where, and From. PowerShell users are still required to use Get-WMIObject or Get-CimInstance to call WQL before being able to use WQL. The parameter -Query must also be used to differentiate between accessing WMI through WQL or through the Class directly. The following WQL example obtains information about the BIOS using the parameter -Query, followed by Select * from and the class name:

Get-WmiObject -Query "Select * from Win32_Bios"
﻿

Comparing WQL, Get-WmiObject, and Get-CimInstance
﻿

There are many situations in which WQL is a better option than Get-WmiObject or Get-CimInstance. The four main differences between WQL and Get-WMIObject and Get-CimInstance include the following:

Syntax

Performance

Debugging

Tab completion 

Table 12.4-2, below, provides additional details about each difference.

﻿

Table 12.4-2﻿

Click "Finish" to exit the event.

﻿Debug a WQL Query
Debug a WQL Query
﻿

Perform troubleshooting to diagnose errors in the WQL syntax provided.

﻿

Workflow﻿

﻿

1. Log in to the VM win-hunt using the following credentials: 

Username: trainee
Password: CyberTraining1!
﻿

2. Open PowerShell as an Administrator.

﻿

3. Enter the following WQL query to filter through a list of processes and only select explorer.exe:

gcim -Query "SELECT * FROM Win32_Process WHERE ProcessID = 'explorer.exe"
﻿

This syntax produces an error that needs to be corrected to work properly. 

﻿

4. Analyze the error output to locate the error in the command entered in the last step.

﻿Debug a Get-CimInstance Query
Debug a PowerShell Get-CimInstance
﻿

Perform troubleshooting to diagnose errors in the Get-CimInstance syntax provided.

﻿

Workflow
﻿

1. Open a new PowerShell window in the VM win-hunt.

﻿

2. Enter the following Get-CimInstance query to filter through a list of processes and only select explorer.exe: 

Get-CimInstance -Class Win32_Processes -Filter "Name = 'explorer.exe'"
﻿

This syntax produces an error that needs to be corrected to work properly. 

﻿

3. Analyze the error output to locate the error in the command entered in the last step.

﻿Use PowerShell to Interact with WMI
In addition to Get-WmiObject and Get-CimInstance, there are many other WMI-specific commands available within PowerShell. This section covers additional commands that defenders may need in the future to accomplish the following:

List additional WMI Cmdlets

List additional available CimCmdlets

Close a running process

Delete a folder

Check whether a file exists

Filter results

List Additional WMI Cmdlets
﻿

The command Get-Command -Noun WMI* displays additional WMI commands, as indicated in Figure 12.4-1, below:

﻿

﻿

﻿Figure 12.4-1﻿

﻿

List Additional Available CimCmdlets
﻿

The command Get-Command -Module CimCmdlets displays multiple options for additional CimCmdlets that are available, as indicated in Figure 12.4-2, below. Two useful commands from this list are Remove-WmiObject and CIM_DataFile, which are covered next.


﻿

﻿

Figure 12.4-2﻿

﻿

Close a Running Process and Delete a Folder
﻿

The command Remove-WmiObject can be used to close a running process or delete a file or a directory, in the following ways:

﻿

Close the Running Process notepad.exe﻿

Get-WmiObject -Query "select * from win32_process where name='notepad.exe'" 
| Remove-WmiObject
﻿

Delete the Folder Test﻿

Get-WMIObject -Query "Select * From Win32_Directory Where Name ='C:\\Test'" 
| Remove-WMIObject
﻿

Defense analysts can use Remove-WmiObject to stop a program on an infected host from running a malicious file and then use the command to remove it from the system through WMI. 

﻿

Check Whether a File Exists
﻿

Another useful class displayed in the CimCmdlets list is CIM_DataFile. This class allows for a fast search across a local host or network to search for specific filenames or file extensions. The following command uses CIM_DataFile to verify whether the file malware.exe exists:

Get-WMIObject -query "select * from CIM_DataFile where Name = 'C:\\malware.exe'"
﻿

﻿

Filter Results
﻿

The results provided by a command often contain more information than required. The parameter -Property filters results to a specific field or a series of fields to provide faster access to only what is needed.

﻿

As an example, running the following command returns five fields:

Get-CimInstance -ClassName Win32_Bios
﻿

However, using the parameter -Property minimizes this further. To return only the field SerialNumber, the command must be piped into Select-Object, as follows:

Get-CimInstance -ClassName Win32_BIOS|Select-Object -Property SerialNumber
﻿

To return a specific selection of fields, such as both SerialNumber and Version, each filtering criteria must be separated by commas. The following is an example of a command that returns only the two fields specified:

Get-CimInstance -ClassName Win32_BIOS|Select-Object -Property SerialNumber, Version
﻿

The parameter -ExpandProperty displays only the results, while omitting the header information. ﻿In addition to omitting headers, -ExpandProperty can extract and display specific values from objects as well as flatten hierarchical data structures. These capabilities are useful for simplifying complex data and focusing on key information. Figure 12.4-3, below, displays the output from -Property with the header “SerialNumber” and the output from -ExpandProperty, which leaves out the header:


﻿

﻿

Figure 12.4-3﻿

﻿

This section touched briefly on piping. Additional information about pipes and pipelines are provided in an upcoming section of this lesson. 

﻿

Access Multiple Remote Hosts﻿

﻿

Providing multiple computer names to the parameter -ComputerName allows the simultaneous retrieval of information from multiple hosts. The following command is an example of retrieving information about the service VolumeShadowCopy on multiple remote hosts using filters and commas:

Get-CimInstance Win32_Service -Filter "Name = 'VSS' -ComputerName RemoteHost,RemoteHost2,RemoteHost3 -Credential $credentials
﻿

Click "Finish" to exit the event.
Auto-Advance on Correct
PowerShell Scripting
The data returned from a PowerShell query is usually output in a table format. The following lab demonstrates how to return a string instead of a table. String data can be read and passed into another script for automation, without requiring additional parsing or removal of table headers.

﻿

Create a PowerShell Script to Return WMI objects from Local and Remote Hosts
﻿

Run the following commands against local and remote hosts to return data as a string. 

﻿

Workflow
﻿

1. Log in to the VM win-hunt using the following credentials: 

Username: trainee
Password: CyberTraining1!
﻿

2. Open PowerShell-ISE as an Administrator.

﻿

3. Create a PowerShell script that collects the operating system information and hostname from both the local machine and two additional remote systems within the network by entering the following series of commands into the top panel of the ISE window:

Import-Module C:\Users\Trainee\Desktop\Lab.ps1

#Remote
Get-Content C:\users\trainee\Desktop\hosts.csv |foreach {invoke-command -scriptblock {Get-CimInstance Win32_OperatingSystem|select-object CSName, Caption|Format-Table -HideTableHeaders} -Credential $creds -ComputerName $_}| Out-File C:\Users\Trainee\Desktop\hostname-os.txt

#Local
Get-CimInstance Win32_OperatingSystem|select-object CSName, Caption|Format-Table -HideTableHeaders | Out-File C:\Users\Trainee\Desktop\hostname-os.txt -Append
﻿

4. Select File from the menu, and choose Run.

﻿

5. Minimize the Powershell ISE window to view the desktop.

﻿

6. Locate and open the new file named hostname-os.txt from the desktop.

﻿

Figure 12.4-4, below, displays the contents of the newly created file for all three systems in the network:


﻿

﻿

Figure 12.4-4﻿

﻿

Click "Finish" to exit the event.














Pipelines
Pipelines ("|") provide the ability to feed data from one command into another for further processing. Common pipelines include Format-Table, Format-List, Select-Object, and Select-String. 

﻿

Format-Table
﻿

The default output of any PowerShell command is Format-Table. This format displays output in a table with headers across the top of the data, as displayed below in Figure 12.4-5. 

﻿

﻿

Figure 12.4-5﻿

﻿

Format-List
﻿

The option Format-List, displayed below in Figure 12.4-6, outputs the data in a list with headers on the left as a column.


﻿

﻿

Figure 12.4-6﻿

﻿

Sort-Object 
﻿

The option Sort-Object sorts the output of the data alphabetically so that it is easier to read. The output can be sorted based on the name of the column. Figure 12.4-7, below, illustrates how the output from the following command sorts all objects based on the column HandleCount:

gcim Win32_Process|Sort-Object HandleCount
﻿

﻿

Figure 12.4-7﻿

﻿

Select-String 
﻿

The option Select-String, illustrated below in Figure 12.4-8, is a command built into PowerShell and searches through the output of a command that is piped into it for matching patterns. This is similar to using the command findstr in a Windows command prompt or the command grep in a Linux terminal.
﻿

﻿




﻿

Figure 12.4-8﻿

Click "Finish" to exit the event.
Auto-Advance on Correct

Get-WinEvent to Filter Windows Event Logs
Filter Windows Event Logs with Get-WinEvent and Select-String
﻿

Obtain objections from the security event log and filter the results by using Select-String.

﻿

Workflow
﻿

1. Log in to the VM win-hunt using the following credentials: 

Username: trainee
Password: CyberTraining1!
﻿

2. Open PowerShell as an Administrator.

﻿

3. View logon events from the security log by entering the following command:

Get-winevent -MaxEvents 200 -filterhashtable @{logname="security";id="4624"}|select-object -expandproperty message
﻿

4. Filter the results to view only the account that logged on by entering the following command:

Get-winevent -MaxEvents 200 -filterhashtable @{logname="security";id="4624"}| select-object -expandproperty message|select-string -Pattern '(Account Name:)(.*)' -All|foreach {$_.Matches.Value}|Sort-Object -Unique
﻿

﻿

5. View the processes that were run during the logon events by running the same command as the previous step, but changing Account Name to Process Name, as follows:

Get-winevent -MaxEvents 200 -filterhashtable @{logname="security";id="4624"}| select-object -expandproperty message|select-string -Pattern '(Process Name:)(.*)' -All|foreach {$_.Matches.Value}|Sort-Object
﻿

Inspect WMI Objects on Hosts
﻿

Identify a remote malicious PowerShell script located on a compromised workstation in the range by inspecting WMI objects on all hosts.

﻿

Workflow
﻿

1. Open PowerShell as an Administrator in the VM win-hunt. 

﻿

2. Create the required variables for authentication to remote hosts by entering the following command:

Import-Module C:\Users\Trainee\Desktop\Lab.ps1
﻿

3. Remotely connect to 172.16.4.2 to gather the stored WMI events by entering the following command:

Invoke-Command -ComputerName 172.16.4.2 -ScriptBlock {Get-CimInstance -Namespace root\subscription -Class __EventConsumer} -Credential $creds
﻿

4. Run the previous command against 172.16.4.9 by entering the following:

Invoke-Command -ComputerName 172.16.4.9 -ScriptBlock {Get-CimInstance -Namespace root\subscription -Class __EventConsumer} -Credential $creds
﻿

The output for 172.16.4.9 reveals the suspicious file calc.exe in an event named LABACTIVITY. This is an example of file-less WMI persistence. The WMI persistence is achieved by T1535-003, Event Triggered Execution: Windows Management Instrumentation Event Subscription, which is a common methodology that attackers use for persistence that does not need executables or other files.
﻿

﻿

5. Compare the output between the two hosts to answer the next question.

﻿
