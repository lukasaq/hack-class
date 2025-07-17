### CDAH-M27L1-Host Isolation Options ###


Host Isolation Considerations
Host isolation is a critical step in the containment phase of IR because it helps prevent the spread of a discovered attack and contain damages. However, IR is a tricky proposition since a responder cannot simply kick a host off the network or power it down without considering the effects of these actions. The isolation technique selected may affect the functionality of the rest of the network or the response plan itself. CDAs must consider the following, prior to selecting a host isolation technique:

Adverse impacts to mission operations
Collateral damage
Evidence collection
Duration of containment
Adverse Impacts to Mission Operations
﻿

The first consideration when an attack is detected is the removal of the attackers from the network. The most direct way to do this is to physically unplug the network cable or disable the interface. However, this might not always be the best first step. The host in question may be mission critical to the organization, so pulling the plug may cause more harm than the attack itself. The attack may even spread beyond the single host where it was discovered, so isolating just one host could be ineffective in containing the attack. 

﻿

Collateral Damage
﻿

CDAs must also consider possible collateral damage for a given strategy. Malware is rapidly becoming more advanced. Advanced malware may be able to detect a containment strategy, change its attack strategy, and cause more negative impacts. For example, disabling a network interface may stop the malware from accessing the Internet, but this may also prompt the malware to delete important information on the host. Predicting the capabilities of the malware is difficult in a case like this. It may be preferable, then, to choose a containment strategy that impacts the operation of the malware as little as possible while still achieving isolation.

﻿

Evidence Collection
﻿

Another consideration when dealing with an incident is evidence collection and preservation. A clumsy approach to containment may corrupt or completely destroy vital evidence. This evidence may be necessary for determining the entire scope of the infection and any potential legal prosecution. Volatile information is lost when powering down a host. This may prevent the collection of information about memory-resident malware.

﻿

Duration of Containment
﻿

The duration of the containment is another important consideration that is difficult to accurately predict. An ideal containment strategy minimally impacts business operations while fully addressing and containing the incident. 

﻿

Overall, the containment strategy employed must take into consideration all of the above factors. CDAs who have a well thought-out and established process prior to an incident are more likely to succeed during incident response. The established process depends on the specific host that is compromised and may have progressive steps based on the duration of the incident response timeline. 


----------------

Host Isolation Techniques
There are many different methods by which a host can be isolated when an attack occurs in an attempt to contain the extent of the malware. The most common mechanisms are network isolation and lateral movement blocking.

﻿

Network Isolation
﻿

Network isolation is the primary method of isolation during incident response. This method is effective because it prevents the infected host from communicating with other hosts on the network. Blocking communication before the malware spreads may effectively contain the infection to a single host. 

﻿

While there are many different ways to accomplish network isolation, the most straightforward method is to disable the network interface. The following describe different options for disabling the network interface:

Physical Removal: Unplug the network cable, if one is available.
Programmed Scripts: Run a script to disable the network interface from the Operating System (OS). 
Logical Partitions: Move the infected host into a separate Virtual Local Area Network (VLAN). 
Firewall Configurations: Set up a firewall on either the host or network to block all traffic into and out of the host. 
In each case, the host ceases all its usual ability to communicate over the network. For an end user workstation, this is likely acceptable. For mission critical servers, this might not be acceptable. Often, the best answer for mission critical servers is to have backup hosts that can take the load while the infected host is isolated. In the absence of proper backup hosts, network isolation may not be a desirable option for host isolation. 

﻿

Lateral Movement Blocking
﻿

Blocking lateral movement is another important part of effective host isolation. After an attacker establishes a foothold on an infected host, blocking lateral movement may help contain the attack and spare the rest of the network. Two common methods for blocking lateral movement are by limiting inter-host communication and by leveraging compromised credentials.

﻿

Limit Inter-Host Communication
﻿

Defenders can block lateral movement by isolating networks, as described above, and by limiting other aspects of inter-host communication. For example, defenders may disable specific protocols, such as Server Message Block (SMB) and Remote Desktop Protocol (RDP). SMB is one of the most common protocols used by attackers for lateral movement in a Windows network environment.

﻿

Leverage Compromised Credentials
﻿

Another common method of lateral movement in an attack is reuse of compromised credentials or leveraging the access of a compromised account to obtain sessions on other computers. Thus, an effective isolation technique could be to disable the compromised accounts. This would allow the host to continue functioning in the network environment as before, just without the compromised account. This would be an effective technique in the case of a compromised account that only has limited privileges and privilege escalation has not yet been accomplished by the attacker. 

﻿

Related to disabling compromised accounts is changing of account passwords. This would be effective in the case of a password breach. Changing the affected passwords would prevent the attackers from being able to use those credentials, limiting them to the access they already have, and preventing them from reusing those passwords to move laterally and expanding their footprint. 

﻿<img width="1096" height="709" alt="image" src="https://github.com/user-attachments/assets/fa6ec280-5c4e-4a35-8224-7509ccc47515" />

------------


Host Isolation With PowerShell
Analysts can use PowerShell to run script commands that logically isolate a device and significantly improve response time during an IR scenario. Since the compromised device is not always physically available, the ability to remotely isolate it before unplugging the network cable is invaluable. There are multiple methods by which a host may be isolated, and applying all of them as a form of defense in depth is appropriate. The following methods may use scripting to isolate the host:

Prevent Outbound Activity

Isolate a Host from a Domain

Turn Off the Network Adapter

Prevent Outbound Activity
﻿

Setting the local and network firewall to prevent all outbound network activity from the isolated device is an effective logical fallback measure to employ. However, this should not be the only measure taken for host isolation. Local firewalls can also be turned off by administrative privileges.

﻿

For example, a mission partner network that employs Vyatta routers for network communications may run the following script to set a firewall rule. This script sets the rule to block a specific Internet Protocol (IP) address from communicating outward:

conf
set firewall name Isolation-Rule default-action 'accept'
set firewall name Isolation-Rule description 'ISOLATED'
set firewall name Isolation-Rule rule 999 action 'drop'
set firewall name Isolation-Rule rule 999 description 'Isolate IP address'
set firewall name Isolation-Rule rule 999 source address 1.2.3.4
set interfaces ethernet eth0 firewall local name Isolation-Rule
commit
save
In a line-by-line manner, this script performs the following actions:﻿

Initiates configuration mode on the device.

Creates the rule set named Isolation-Rule and sets the default action to accept so that traffic not explicitly blocked by other rules is allowed.

Sets the description of the rule to ISOLATED.

Creates a rule with ID 999 within the Isolation-Rule set to drop matching traffic.

Sets the description of rule 999 to Isolate IP address.

Specifies that the source address of rule 999 is 1.2.3.4.

Associates the Isolation-Rule set with eth0 on the firewall.

Applies the configuration changes.

Saves the configuration changes.

Using an address group improves the extensibility of this rule. The current rule requires adding a new numbered rule to the firewall with each additional isolation. Additional isolations may be necessary during a widespread compromise.

﻿

Isolate a Host from a Domain
﻿

Removing a host from the domain prevents domain-authenticated communications. This effectively makes the device unusable because authentication cannot occur. 

﻿

Use the PowerShell cmdlet Remove-Computer to remove a computer from the domain. This cmdlet uses the parameters listed in Table 27.1-1, below, to receive the necessary input from the user and remove a host from the domain:

<img width="1667" height="887" alt="image" src="https://github.com/user-attachments/assets/418ee210-9402-4a68-8c0c-8a56f1497576" />


Turn Off the Network Adapter


Network connectivity at the host level must be severed as completely as possible. Although removing the physical cable from the system is the best way to accomplish this, there are other effective backups defenders can use until responders arrive onsite. One option is to logically turn off the network adapter for all network interface cards. Defenders can run the following command in PowerShell to turn off the cards:
Disable-NetAdapter -Name "Device Name" -Confirm:$false



After the incident is resolved, defenders may use the following command to re-enable the device:
Enable-NetAdapter -Name "Device Name" -Confirm:$false


---------------


Develop a PowerShell Isolation Tool
The previous sections of this lesson described various methods for isolating a computer. In the following lab, write a script to turn off the network adapter, remove the computer from the domain, and prevent the computer from communicating in any other way on the network, even if the adapter is turned on or any cables are reconnected.

﻿

Workflow
﻿

1. Log in to the Virtual Machine (VM) dc01 using the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Open the PowerShell Integrated Scripting Environment (ISE).

﻿

3. Define the following user-supplied parameters:

param(
    [Parameter()]
    [String]$ComputerName,
    [String]$RouterIP,

    [String]$UserName,
    [String]$Password
)
﻿

4. Enable PowerShell cmdlets to manipulate Active Directory (AD) objects by importing the following AD module:

Import-Module ActiveDirectory
﻿

5. Obtain the IP address of the isolated computer by defining the following variable:

$ComputerIP = $(Resolve-DnsName $ComputerName).IPAddress
﻿

6. Turn off the network adapter in five minutes by entering the following script: 

Invoke-Command -ComputerName $ComputerName -ScriptBlock {Register-ScheduledTask -TaskName 'Isolate' -InputObject ((New-ScheduledTask -Action (New-ScheduledTaskAction -Execute 'pwsh.exe' -Argument '-Enable-NetAdapter -Name "Ethernet1" -Confirm:$false') -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)) -Settings (New-ScheduledTaskSettingsSet))) -User $Using:UserName -Password $Using:Password}
﻿

The following is the script block broken down into its discrete parts: ﻿﻿

﻿

Execute everything within the script block as the current domain administrator:

Invoke-Command -ComputerName $ComputerName -ScriptBlock { 
﻿

Register and create a scheduled task on dc01:

Register-ScheduledTask -TaskName 'Isolate' -InputObject ((New-ScheduledTask 
﻿

Isolate the network adapter on the malware-infected host:

-Action (New-ScheduledTaskAction -Execute 'pwsh.exe' -Argument '-Enable-NetAdapter -Name "Ethernet1" -Confirm:$false') 
﻿

Set the task to execute in five minutes:

-Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date)AddMinutes(5))
﻿

Call the new scheduled task setting function:

-Settings (New-ScheduledTaskSettingsSet)))
﻿

Execute the task creation process with administrator privileges and end the script block:

-User $UserName -Password $Password}
﻿

NOTE: In some situations it is wise to avoid running commands on the infected computer. If forensic data collection has not yet been completed, running new code or making configuration changes might negatively affect the value of the forensic data. If touching the infected host is inadvisable or disallowed, the remote commands in the code above can be excluded from the script. The firewall rules created in later steps will also effectively disconnect the infected host from the network. 

﻿

7. Remove the malware-infected host from the domain and have it join the workgroup Isolated by entering the following PowerShell cmdlet:

Remove-Computer -ComputerName "$ComputerName" -UnjoinDomainCredential energy\trainee -WorkgroupName "Isolated" -Force
﻿

NOTE: A best practice is to restart the device after making domain membership changes to the host. However, in this scenario, the restart is being delayed until the IR team arrives at the workstation location and completes the necessary forensics.

﻿

So far, the script turns off the network adapter and removes the computer from the domain. The next series of commands aims to prevent the computer from communicating in any other way on the network. This also prevents the attacker from restoring connectivity prior to the IR team resolving the incident. To achieve these goals, the next part of the script sets up a firewall rule on the router to block all network traffic from the intruder IP address.

﻿

This part of this lab uses the Putty Secure Shell (SSH) client. This SSH client is installed on the current domain controller (dc01), though it is not commonly present in default installations of Windows server or Windows workstations. In this case, Putty SSH has been installed to extend the functionality of the isolation script by enabling remote interaction with the router which governs network connectivity to the host in question. 

﻿

Analysts are able to use the command plink from within a PowerShell script to SSH into the Vyatta router and configure firewall rules that isolate the malware-infected system. The configuration passed to the router creates a firewall rule that denies all traffic from a Domain Name Server (DNS)-resolved IP address and applies that rule to all interfaces.

﻿

8. SSH into the router by entering the following command in the script:

plink -ssh vyatta@$RouterIP -i $env:UserProfile\id.ppk -batch 
﻿

9. Use the configuration command wrapper to pass commands to the Vyatta router with the wrapper command begin by entering the following command in the script:

"/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper begin; 
﻿

10. Create the firewall address group ISOLATED with the host IP or IP range to isolate and set a description for the group:

/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set firewall group address-group ISOLATED address $ComputerIP; 
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set firewall group address-group ISOLATED description 'Isolated IP Addresses';
﻿

11. Under the address group ISOLATED, create a rule named Isolation-Rule that accepts traffic by default, then sets a description:

/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set firewall name Isolation-Rule default-action 'accept';
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set firewall name Isolation-Rule description 'ISOLATED';
﻿

Creating an address group allows engineers and administrators to quickly reduce overhead by centrally managing individual IPs and IP ranges without manually updating each rule. The rule created in the next step uses the address group through its name, Isolation-Rule, to set the IP or IP range the rule applies.

﻿

12. Create a new rule numbered 999 that drops all network traffic from the infected host:

/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set firewall name Isolation-Rule rule 999 action 'drop';
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set firewall name Isolation-Rule rule 999 description 'Isolate IP address';
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set firewall name Isolation-Rule rule 999 source group address-group ISOLATED;
﻿

The next step applies this rule to the interfaces to prevent the infected host from communicating across the network.

﻿

13. Apply the created firewall rule to the seven available interfaces by entering the following set of commands in the script:

/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set interfaces ethernet eth1 firewall local name Isolation-Rule;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set interfaces ethernet eth2 firewall local name Isolation-Rule;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set interfaces ethernet eth3 firewall local name Isolation-Rule;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set interfaces ethernet eth4 firewall local name Isolation-Rule;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set interfaces ethernet eth5 firewall local name Isolation-Rule;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set interfaces ethernet eth6 firewall local name Isolation-Rule;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set interfaces ethernet eth7 firewall local name Isolation-Rule;
﻿

14. Commit and save the configuration changes by entering the following commands in the script:

/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper commit;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper save;"
﻿

15. Ensure all lines of the script from the previous steps have been entered correctly by comparing them to the following completed script:

param(
    [Parameter()]
    [String]$ComputerName,
    [String]$RouterIP,
    [String]$UserName,
    [String]$Password

)

Import-Module ActiveDirectory

$ComputerIP = $(Resolve-DnsName $ComputerName).IPAddress

Invoke-Command -ComputerName $ComputerName -ScriptBlock {Register-ScheduledTask -TaskName 'Isolate' -InputObject ((New-ScheduledTask -Action (New-ScheduledTaskAction -Execute 'pwsh.exe' -Argument '-Enable-NetAdapter -Name "Ethernet1" -Confirm:$false') -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5)) -Settings (New-ScheduledTaskSettingsSet))) -User $Using:UserName -Password $Using:Password}

Remove-Computer -ComputerName "$ComputerName" -UnjoinDomainCredential energy\trainee -WorkgroupName "Isolated" -Force

plink -ssh vyatta@$RouterIP -i $env:UserProfile\id.ppk -batch "/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper begin; /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set firewall group address-group ISOLATED address $ComputerIP; 
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set firewall group address-group ISOLATED description 'Isolated IP Addresses';
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set firewall name Isolation-Rule default-action 'accept';
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set firewall name Isolation-Rule description 'ISOLATED';
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set firewall name Isolation-Rule rule 999 action 'drop';
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set firewall name Isolation-Rule rule 999 description 'Isolate IP address';
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set firewall name Isolation-Rule rule 999 source group address-group ISOLATED;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set interfaces ethernet eth1 firewall local name Isolation-Rule;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set interfaces ethernet eth2 firewall local name Isolation-Rule;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set interfaces ethernet eth3 firewall local name Isolation-Rule;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set interfaces ethernet eth4 firewall local name Isolation-Rule;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set interfaces ethernet eth5 firewall local name Isolation-Rule;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set interfaces ethernet eth6 firewall local name Isolation-Rule;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set interfaces ethernet eth7 firewall local name Isolation-Rule;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper commit;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper save;"
﻿

16. Save the entire PowerShell script on the Desktop with the file name IsolateHost.ps1.

﻿

Execute the PowerShell Isolation Tool
﻿

Continue working in the VM dc01 to run the script IsolateHost.ps1 in PowerShell ISE. Use the VM core-router to verify that the script executes correctly.

﻿

NOTE: Executing the script in PowerShell ISE configures the router. This displays warnings regarding rules already existing and generates Invalid command [] errors due to a software bug in the current software version. For this lab, ignore the warnings and errors that display during script execution.

﻿
Workflow
﻿

1. In the VM dc01, execute the script IsolateHost.ps1 within the PowerShell ISE terminal by entering the following commands:

cd c:\Users\trainee\Desktop
.\IsolateHost.ps1 -ComputerName ENG-WKSTN-1 -RouterIP 172.16.2.1 -UserName Administrator -Password CyberTraining1!
﻿

Enter CyberTraining1! if prompted for a password.

﻿


This command executes the script IsolateHost.ps1 for the host ENG-WKSTN-1 at the router located at IP address 172.16.2.1.

﻿

2. Login to the VM core-router with the following credentials

Username: vyatta
Password: simnet
﻿

3. Verify the script executed correctly by entering the following two commands:

configure 
show firewall
﻿

The address-group ISOLATED should be visible with the configured IP address 172.16.4.2﻿

﻿

show interfaces
﻿

The output for a correct execution indicates that the firewall local name Isolation-Rule applies to the ethernet adapters eth1 through eth7.

<img width="801" height="141" alt="image" src="https://github.com/user-attachments/assets/0edad5d7-1449-4682-9077-ca27934d3148" />
<img width="1110" height="491" alt="image" src="https://github.com/user-attachments/assets/7cad63fb-9d59-44a0-bc3d-d9dcab70c2fd" />


-----------


Resolve an Intrusion Incident
Analysts may return an isolated host back into the organization’s operating environment after concluding the incident that required host isolation. An incident is concluded when one or more of the following conditions are met:

The system was restored completely from a backup image after collection occurred.
The system was thoroughly investigated and all malicious artifacts were eradicated.
The contaminated objects, such as user accounts, have undergone sufficient state change from the time of compromise, including password changes.
Developing a PowerShell Restoration Tool
﻿

An incident has concluded. A host requires the restoration of full connectivity to the network. Use PowerShell to develop a script that aids by automating the restoration process. 

﻿

Workflow
﻿

1. Log in to the VM dc01 using the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Open the PowerShell ISE. 

﻿

3. Define the following user-supplied parameters:

param(
    [Parameter()]
    [String]$ComputerName,
    [String]$RouterIP
)
﻿

4. Import the Active Directory module by entering the following cmdlet:

Import-Module ActiveDirectory
﻿

5. Turn network access to the device back on at the router level by entering the following series of commands:

﻿

NOTE: Executing these commands displays warnings and generates Invalid command [] errors due to a software bug in the current software version. For this lab, ignore the warnings and errors that display during script execution.

﻿

plink -ssh vyatta@$RouterIP -i $env:UserProfile\id.ppk -batch "/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper begin; /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper delete firewall group address-group ISOLATED;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper delete firewall name Isolation-Rule;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper delete interfaces ethernet eth1 firewall local name Isolation-Rule;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper delete interfaces ethernet eth2 firewall local name Isolation-Rule;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper delete interfaces ethernet eth3 firewall local name Isolation-Rule;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper delete interfaces ethernet eth4 firewall local name Isolation-Rule;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper delete interfaces ethernet eth5 firewall local name Isolation-Rule;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper delete interfaces ethernet eth6 firewall local name Isolation-Rule;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper delete interfaces ethernet eth7 firewall local name Isolation-Rule;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper commit;
/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper save;"
﻿

6. Add the host back into the domain by entering the following cmdlet:

Add-Computer -ComputerName $ComputerName -LocalCredential $ComputerName\Administrator -DomainName energy.lan -Credential energy\trainee -Restart -Force
﻿

7. Save the file on the Desktop as RestoreIsolatedHost.ps1.

﻿

8. Log in to the VM eng-wkstn-1 with the following credentials: 

Username: trainee
Password: CyberTraining1!
﻿

9. Open a PowerShell terminal.

﻿

10. Turn on the Network Adapter by entering the following cmdlet:

Enable-NetAdapter -Name "Ethernet1" -Confirm:$false
﻿

11. Return to the VM dc01.

﻿

12. In a PowerShell terminal, execute the script RestoreIsolatedHost.ps1 for the host eng-wkstn-1:

.\RestoreIsolatedHost.ps1 -ComputerName ENG-WKSTN-1 -RouterIP 172.16.2.1
﻿

13. Enter CyberTraining1! when prompted for Administrator and Trainee passwords.

﻿

Use the information from this lab to answer the following question.

<img width="1118" height="715" alt="image" src="https://github.com/user-attachments/assets/11a78a23-046c-49cb-b307-e37ffefd0467" />


------------

### CDAH-M27L2-Forensic Image Acquisition ###

Forensic Acquisition Overview
Forensic acquisition is the process of collecting and creating a bit for bit copy of data from a specified storage device or host. Forensic acquisition is accomplished using two primary methods: memory acquisition and disk image acquisition. Once the acquisition has been completed, the data must be authenticated through hashing. Verifying the integrity of a forensic image through hashing maintains confidence in the reliability and authenticity of the acquired data. By comparing the hash value of the acquired forensic image with the known reference value, investigators can quickly determine whether the image has remained unchanged or if any modifications have been introduced.

﻿

Memory Acquisition
﻿

Volatile memory, or Random Access Memory (RAM), is the memory used by the host in a powered-on state. Memory acquisition is the process of copying the data stored in the volatile memory of a host. For most operating systems, the data is stored in volatile memory, RAM, and is lost when a host loses power or is shut down. Memory acquisition effectively copies data from a volatile state to a non-volatile state and is completed by a memory dump, which may occur in one of several formats: RAW, crash dump, hibernation file, page file, or virtual snapshot. Each format is unique and may be available on only certain Operating Systems (OS). 

﻿

RAW File
﻿

A RAW-format memory dump is manually extracted from OSs in a live environment. A .raw file contains uncompressed and unprocessed data captured from the host. When memory is dumped using the RAW format, the data does not contain a header, metadata, or supporting information. 

﻿

Crash Dump
﻿

A crash dump is a memory dump of information collected by the OS about the host’s physical memory. The Windows OS, by default, collects information about the system in the event of a system crash. A Windows OS crash dump is usually saved in the C:\Windows\MEMORY.DMP file. Linux crash dumps are usually found in the /var/crash/ directory named as .crash files.

﻿

Hibernation File
﻿

A hibernation file is a snapshot of the host’s memory that the Windows OS collects and can return after a hibernation period. The hibernation file, hiberfil.sys, is a binary file located in the root directory (%SystemDrive%/hiberfil.sys). If hibernation is enabled on the host, the file is captured when an image, or copy, of the Hard Disk Drive (HDD) or Solid-State Drive (SSD) is created.

﻿

Page File
﻿

Page files (swap files) enable a system to place infrequently accessed information from RAM to a file on a non-volatile storage device, like a hard disk drive, letting the system use volatile RAM more efficiently. While a 64-bit system with a significant physical RAM capacity may not require a page file, the page file still plays a critical role in extending the system commit limit and supporting crash dumps as necessary, essentially serving as overflow for RAM. While users can create page files, most system administrators disable this ability through security policies. Additionally, administrators may elect to store page files on physical media outside the system architecture as an additional security measure or for performance gains. However, moving the page file from the C:\ drive on a Windows system is usually only done for critical infrastructure and heavy-load assets, not for user workstations. The CPT should coordinate with the mission partner to ascertain the location of all essential files when conducting forensic acquisition.

﻿

Virtual Snapshot
﻿

A virtual snapshot is a saved state of a Virtual Machine (VM) at a specific point in time. A virtual snapshot allows users to re-create the VM in the exact state in which the snapshot was captured. 

﻿

Table 27.2-1 provides a summary of the memory acquisition file formats described above:

<img width="1667" height="1058" alt="image" src="https://github.com/user-attachments/assets/dae9cd8d-a4a4-4fdb-a1d9-43500412e0e9" />

Disk Image Acquisition


Disk image acquisition is the process of copying all data, sector by sector, present on the host’s HDD. An HDD contains the host’s non-volatile memory. Disk imaging is thorough in its copying, as it copies data from sectors, including physical and logical drives, active file systems, and unused areas of the drive. Although disk imaging is thorough, it is also resource heavy, requiring significant time and memory resources to execute. Disk imaging acquisition occurs through various techniques:

Disk-to-disk: Uses hardware to create an exact copy of a source hard drive.
Disk-to-image: Makes a copy of a hard disk and saves the data as a file, such as an Optical Disk Image, or ISO, file. 
Logical: Creates a bit-for-bit copy of the data from only specific files or artifacts of interest. 
Sparse: Targets specific files and collects fragments of unallocated or deleted data. 


----------------

Volatile Memory vs. Hard Disk Acquisition
Recommending a particular forensic acquisition methodology depends on the details, components, and complexity of the incident. Table 27.2-2 provides factors that must be considered when recommending a forensic acquisition strategy:

<img width="1667" height="858" alt="image" src="https://github.com/user-attachments/assets/1d6533cf-5bef-49b4-8cca-53bec160a3a3" />
<img width="1131" height="683" alt="image" src="https://github.com/user-attachments/assets/7963a6a7-539f-4030-bc50-d69d0f5b2306" />


-----------

Identify a Compromised Host
Read the scenario below, and complete the steps in the workflow to analyze and identify the infected host(s) on the network.

﻿

Scenario
﻿

An analyst in the Security Operations Center (SOC) noticed unusual traffic during an organizational off-day. The SOC analyst tracked the suspicious traffic from the 172.16.4.0/24 Engineer subnet. As a result, the organization has implemented its IR procedures. The Cyber Protection Team (CPT) is tasked with identifying any infected hosts and relevant information to determine initial access and the best forensic acquisition method. Each workstation is providing Packetbeat, Winlogbeat, and Sysmon data to the Security Information and Event Manager (SIEM).  

﻿

Workflow
﻿

1. Open the VM win-hunt. The login credentials are as follows:

Username: trainee
Password: CyberTraining1!
﻿

2. Open the Chrome browser.

﻿

3. Select the 1 - DashBoard - Security Onion bookmark.

﻿

4. Log in to the Security Onion Console with the following credentials:

Username: trainee@jdmss.lan
Password: CyberTraining1!
﻿

5. On the main dashboard, adjust the time frame to Oct 4, 2022 @ 05:00:00.000 → Oct 4, 2022 @ 17:00:00.000, and document the entries in the dataset for Log Count by Node.

﻿

6. Select Network under Event Category:

﻿
<img width="337" height="203" alt="image" src="https://github.com/user-attachments/assets/021cd5e3-41d6-4423-84dc-92d6c237e656" />



7. Ensure the time frame is still filtering for Oct 4, 2022 @ 05:00:00.000 → Oct 4, 2022 @ 17:00:00.000, and select an Internet Protocol (IP) address in the dataset Source IPs.


8. Observe the IPs in the dataset Destination Ports.


9. Select the 2 - Kibana Discover - Elastic bookmark. Using the *:so-* index, set the time frame to Oct 4, 2022 @ 05:00:00.000 → Oct 4, 2022 @ 17:00:00.000. 


10. Select and add the following columns to the search index: 
source.ip
source.port
agent.type
destination.ip
destination.port

11. Add the following filter to the query to show only data containing destination port traffic:
destination.port exists



12. With the columns added to the index from Step 10, perform a search for the main traffic generated by the Engineer subnet, using the following search criteria: 
destination.port : <ports identified in Step 8> 
network.data.decoded : GET
destination.port : <port> and event.dataset.keyword :* exe
event.provider : Microsoft-Windows-Sysmon


Use the data returned from the query to answer the following questions.

<img width="1917" height="696" alt="image" src="https://github.com/user-attachments/assets/9b79639a-39a9-4a0c-bac0-2ad8271f4e6e" />
<img width="1082" height="470" alt="image" src="https://github.com/user-attachments/assets/e0084b1c-ca8d-4029-841b-4e84d4a817c3" />
<img width="1910" height="696" alt="image" src="https://github.com/user-attachments/assets/063c2617-0c76-46f9-9bb2-a3075510f967" />
<img width="1115" height="659" alt="image" src="https://github.com/user-attachments/assets/54e03f98-48bb-4306-a876-797d05fd1855" />
<img width="1893" height="622" alt="image" src="https://github.com/user-attachments/assets/6067b55a-e961-4c7b-b80a-b9da1ef40034" />
<img width="1112" height="530" alt="image" src="https://github.com/user-attachments/assets/2abc3555-12cf-4ff9-96c7-4b0a0485a20d" />
<img width="1112" height="449" alt="image" src="https://github.com/user-attachments/assets/298a4273-b599-4b15-bc13-734f0bad5bfd" />
<img width="1126" height="671" alt="image" src="https://github.com/user-attachments/assets/3d428fc4-2b90-4899-8c0f-5fc73eb42dd0" />


--------------------


Acquisition Strategy during an Active Breach
Acquisition strategy during an active breach requires deliberate and thorough actions. An active breach means that the adversary is currently present in the network. While active in the network, the adversary may keep a keen eye out, looking for actions that indicate that they have been found and an investigation has begun. If discovered by the owners of the victim network, the adversary may attempt immediate actions to remove their presence or steal valuable data. Table 27.2-3 provides factors the adversary may attempt to identify:

﻿<img width="1667" height="717" alt="image" src="https://github.com/user-attachments/assets/8cbb8bc7-bb83-4ae9-897e-bf727b089623" />

Techniques to Avoid Adversary Detection


IR teams must consider the actions the adversary may look for while maintaining a foothold in the network. Although the top priorities remain driving the adversary out of the network and preventing further damage, IR teams must act with intention, revealing themselves to the adversary only when they have complete control of the situation. Table 27.2-4 provides techniques IR teams may implement to avoid alerting the adversary of detection:


<img width="1667" height="992" alt="image" src="https://github.com/user-attachments/assets/208b8b9c-f801-43de-bded-68698d1b56cf" />


---------------

IR Evidence Acquisition during an Active Breach
Read the scenario below, and complete the steps in the workflow to discover forensic artifacts during an active breach.

﻿

Scenario
﻿

A malicious actor has compromised the eng-wktsn-1 system. Analysts have acquired a system image of the infected machine and built an isolated VM for further analysis. After reviewing available network logs, Network Analysts have posited that, based on the C2 activity, the malware attacked a remotely exploitable vulnerability and has developed persistence from memory. Still, the team is missing complete details about the malware. Conduct a memory dump using Redline, a tool for finding signs of malicious activity through memory and file analysis.

﻿

Workflow
﻿

1. Open the VM eng-wkstn-1. The login credentials are as follows:

Username: trainee
Password: CyberTraining1! 
﻿

2. Create a folder on the desktop, and name it Memory Analysis 2. (This folder is used in a later step.) 

﻿

3. Open Redline, and select Create a Standard Collector.

﻿

4. Under Review Script Configuration, select the checkbox under Acquire Memory Image. Select the newly created folder Memory Analysis 2 as the destination to save the collector, and select OK:


<img width="1437" height="1015" alt="image" src="https://github.com/user-attachments/assets/7a8267a3-c8a7-4532-ac3d-5b9fb5c683f6" />


5. Once OK has been selected, Redline provides a pop-up window detailing collector instructions. In the pop-up window, select the link Open Directory Containing Portable Package. This opens the Memory Analysis 2 folder.


<img width="984" height="588" alt="image" src="https://github.com/user-attachments/assets/779ea2ad-9359-4cd7-8582-62ba18ff4645" />

6. Return to Redline, exit any menus or pop-up windows, and return to the main Redline dashboard. This is a housekeeping step to close open dialog windows. 


7. Return to the Memory Analysis 2 folder, right-click the Windows batch file RunRedlineAudit, and select Run as administrator

<img width="613" height="337" alt="image" src="https://github.com/user-attachments/assets/6117aa77-4499-4268-ab2b-2064ed0fa3fb" />

A Command-Line Interface (CLI) window opens and begins executing the selected Redline analysis options. 


8. Allow the CLI prompt to complete its run. Once it has completed, return to the Redline application. 


NOTE: Depending on the physical components and amount of RAM installed, this process may require 1 hour to 24 hours to complete. 


NOTE: For the current component configuration of eng-wkstn-1, along with the selected Redline options, analysis requires up to 8 hours to complete. This lesson’s analysis has already been performed for efficiency and time constraints. The following steps continue from the point at which the report is completed and is ready for review. 


9. In the Redline dashboard, select AnalysisSession1.mans under Recent Analysis Sessions.



After this memory analysis report opens, an interactive interface displaying the selected Standard Collector options appears.


10. In the Analysis Data pane of the interface, select Processes to expand the Processes option. Review the processes to identify the malicious process.

<img width="313" height="205" alt="image" src="https://github.com/user-attachments/assets/8760d4a5-9e8f-4b2d-82f2-d6578934051f" />


The use of filters aids in identifying malicious information. For example, a filter can be created on each column, such as the Username column, to display only processes belonging to a specific user account. 


11. To create a filter for the trainee user account, select the funnel icon in the Username column; select contains in the drop-down menu; enter trainee in the dialog box; and select Add Filter


<img width="945" height="244" alt="image" src="https://github.com/user-attachments/assets/cf75def0-fd8d-4a81-b996-556e22252c57" />



12. Conduct analysis of ports used by processes by selecting the Ports option in the Analysis Data pane. All ports, only listening ports, or only ports with established connections may be displayed. 


Use this workflow to answer the following questions


<img width="1916" height="833" alt="image" src="https://github.com/user-attachments/assets/56f5c910-ce83-4b0b-97cf-ff331e5fe429" />
<img width="1114" height="718" alt="image" src="https://github.com/user-attachments/assets/5e7e6cb2-6e71-47e6-bc7a-e4bc9e6d6e8c" />
<img width="1040" height="410" alt="image" src="https://github.com/user-attachments/assets/54aa46ec-5fc2-423f-a40a-66c69b012d4e" />
<img width="1913" height="828" alt="image" src="https://github.com/user-attachments/assets/bf4d792b-9450-4a46-9cc0-538937e968da" />
<img width="1106" height="524" alt="image" src="https://github.com/user-attachments/assets/127dcc0a-f3fd-493f-8307-5513153cdd16" />

---------------


### CDAH-M27L3-Preserve Logs in Incident Response ###

Challenges in Acquiring Logs
Log collection is a critical component of monitoring and responding to incidents on the network. Logs can show such key data points as events, network connection, and processes that can assist the IR team. Log collection does have challenges, and Table 27.3-1 includes factors that organizations must remember when collecting logs


<img width="2500" height="1635" alt="image" src="https://github.com/user-attachments/assets/b6bc707b-2a77-439a-9cd5-295210c50552" />


Log Integrity


When log challenges are considered and addressed thoughtfully, the result is high log integrity. Log integrity is the collection of log data that is accurate, true, and uncontaminated. Log data with high integrity allows for the data to be used as evidence due to the trust in the collection process and data handling. An additional benefit of high log integrity is reduced time to prepare and execute an investigation. When log data is accurate and efficiently collected, an investigation can start promptly.


--------------


Analyze Compromised Logs
Based on the scenario below, complete the steps in the following workflow to identify and analyze compromised host logs.

﻿

Scenario
﻿

The host bp-wkstn-3 contains malware, the effects of which are currently unknown. Investigate bp-wkstn-3 using Kibana to discover the malware's impact on log collection. Use host eng-wkstn-2 as a comparison baseline of proper log collection.

﻿

In Kibana, customize the Discover view and use the search function to identify if any Windows Logs have been cleared.

﻿

Workflow
﻿

1. Open the Virtual Machine (VM) win-hunt. The login credentials are as follows:

Username: trainee
Password: CyberTraining1!
﻿

2. Open the Chrome browser.

﻿

3. Select the Discover - Elastic bookmark.

﻿

4. Log in to the Security Onion Console (SOC) with the following credentials:

Username: trainee@jdmss.lan
Password: CyberTraining1!
﻿

5. Set the search time frame as Sep 21, 2022 @ 00:00:00.000 to Sep 21, 2022 @ 23:30:00.000. 

﻿

6. Select Filter by type, then set the Hide Missing Fields toggle button to Off.

﻿

7. Select and add the following columns:

agent.name 
agent.type
event.code
event.action
event.dataset
event.module
log.level

8. Using the *:so-* index, execute the following query in SOC:

event.code: 1102 or event.code: 104 or event.code: 517 
﻿

Event codes 1102, 104, and 517 indicate logs were cleared from the host.

﻿


Use the data returned from the query to answer the following questions.
<img width="1909" height="709" alt="image" src="https://github.com/user-attachments/assets/cda69728-29a0-4306-ab56-03d4571d7e68" />

<img width="1077" height="448" alt="image" src="https://github.com/user-attachments/assets/07df443c-6b93-4c35-bc93-151556574b82" />


-----------------


Compromised Host
Host bp-wkstn-3 is compromised with malware that is modifying or deleting logs. As shown in Figure 27.3-1, bp-wkstn-3 experiences multiple Log clear events, preventing log collection from occurring as expected: 

﻿
<img width="1846" height="759" alt="image" src="https://github.com/user-attachments/assets/c7a5c932-95e9-47b1-92f0-21ce77fcf305" />
<img width="1909" height="709" alt="image" src="https://github.com/user-attachments/assets/533db269-615f-40d3-973b-76d4fc3ddefc" />

<img width="1070" height="632" alt="image" src="https://github.com/user-attachments/assets/9c1a0cd3-956f-4ceb-8b4a-8c192eb08702" />
<img width="1091" height="502" alt="image" src="https://github.com/user-attachments/assets/89515e6a-089f-4583-94d7-3516fbdea787" />

-------

Activity Cleared
As seen in Figure 27.3-2 below, the event.dataset and agent.name fields indicate that bp-wkstn-3 experienced multiple Log clear events in both the Security and System log categories. 

﻿

The agent.type field shows that the Log clear events w ere collec ted, transported, and preserved using Winlogbeat.
<img width="1451" height="547" alt="image" src="https://github.com/user-attachments/assets/05e24607-66d6-433c-972d-a1f22dd1c54a" />


--------------

Analyze Winlogbeat
Complete the steps in the following workflow to determine which logs are shipped via analysis of the Winlogbeat configuration files.

﻿

Workflow 
﻿

1. Open the VM bp-wkstn-3. The login credentials are as follows:

Username: administrator
Password: CyberTraining1!




2. Open File Explorer, and ensure the Hidden Items box is checked under the View tab.

﻿

3. Navigate to the C:\ProgramData\Elastic\Beats\winlogbeat folder.

﻿

4. Right-click the winlogbeat.yml file, and copy and paste it on the desktop.

﻿

5. Right-click the winlogbeat.yml file on the desktop, select Open with, select More apps, select Notepad, uncheck Always use this app to open .yml files, and select Open.

﻿

6. Review the configuration file, and answer the following question.

<img width="1920" height="837" alt="image" src="https://github.com/user-attachments/assets/e2b091b2-14ad-4747-9e60-e851665369cf" />
<img width="1098" height="422" alt="image" src="https://github.com/user-attachments/assets/47bfcaf4-5f9f-4902-9a7e-39639e6e8f45" />





---------

Identify Modified Logs
Use PowerShell cmdlets to identify log acquisition challenges based on the scenario below.


﻿

Scenario
﻿

The host bp-wkstn-3 contains malware, the effects of which are currently unknown. Investigate bp-wkstn-3 using PowerShell cmdlets to discover the malware's impact on log collection. Use host bp-wkstn-1 as a comparison baseline of proper log collection.

﻿

Compare the PowerShell cmdlet output between bp-wkstn-1 and bp-wkstn-3, and determine the status of logging services. 

﻿

Workflow 
﻿

1. Open the VM bp-wkstn-1 using the Administrator account. The login credentials are as follows:

Username: trainee
Password: CyberTraining1!
﻿

2. Open a PowerShell prompt as an Administrator, and enter the following cmdlets:

get-eventlog -list; get-service "ev*" | sort-object status
﻿

3. Open the VM bp-wkstn-3. The login credentials are as follows:

Username: administrator
Password: CyberTraining1!
﻿

4. Open a PowerShell prompt as an Administrator, and enter the following cmdlets:

get-eventlog -list; get-service "ev*" | sort-object status
﻿

5. Start the stopped service using the start-service -name "ServiceName" cmdlet. 

﻿

6. Use the services.msc command to open the Microsoft Management Console (MMC) snap-in for managing Windows services. 

﻿

7. Locate and examine the Windows Event Log service to determine the startup type. 

﻿

The host bp-wkstn-1 has cleared the proper IR protocol and is free from malware. The host bp-wkstn-3 has not cleared the IR protocol and still contains malware. 

﻿

Use the data returned from the cmdlets to answer the following question.

<img width="1113" height="660" alt="image" src="https://github.com/user-attachments/assets/c02d08f8-0112-4142-95bd-a0ff21a0973d" />
<img width="1099" height="408" alt="image" src="https://github.com/user-attachments/assets/6ec5eec7-1d6d-47d4-afca-d50c0d4c7636" />



-----------------------

Challenges in Preserving Logs
Log preservation is a critical component that allows CDAs to monitor and investigate activity on the network. Logs must be stored and be easily accessible to network defenders. Like log collection, log preservation has its challenges, and Table 27.3-2 includes factors that organizations must remember when preserving logs: 


<img width="2500" height="1264" alt="image" src="https://github.com/user-attachments/assets/9d1eb5d0-3def-4e5c-bd39-cea39a4df213" />


Preservation Techniques


Log preservation relies on a predetermined set of parameters that define which data is preserved, where the data is stored, and how long the data is maintained. Once the parameters have been determined, it is critical that an organization creates redundant processes to ensure that data is not lost due to a single point of failure. To create redundancy, organizations may develop a backup storage location for logs. The storage location may be located on an additional server or on the host itself. When logs are collected on the host, they may be duplicated and sent to both the primary server and the backup location. Such tools as Task Scheduler and PowerShell may be used to automate the backup collection.


---------------


Confirm Modification of Logs
Based on the scenario below, complete the steps in the following workflow to resume analysis of the malware attack using the VM win-hunt. 

﻿

Scenario 
﻿

Due to the malware attack, system and security logs on bp-wkstn-3 were cleared, and the Windows Event Log service was disabled. These actions have caused a significant gap in the log data, posing a challenge for any post-incident analysis. 

﻿

Analyze the available logs in the Elastic Stack from bp-wkstn-3, identify the timeline of events, and determine the extent of the logging interruption. Use bp-wkstn-1 as a comparison baseline. 

﻿

Workflow 
﻿

1. Open the VM win-hunt. The login credentials are as follows:

Username: trainee
Password: CyberTraining1!
﻿

2. Open the Chrome browser.

﻿

3. Select the Discover- Elastic bookmark.

﻿

4. Log in to the Security Onion Console (SOC) with the following credentials:

Username: trainee@jdmss.lan
Password: CyberTraining1!
﻿

5. Set the search time frame to Sep 21, 2022 @ 00:00:00.000 to Sep 21, 2022 @ 23:30:00.000.  

﻿

6. Select Filter by type, then set the Hide missing fields toggle button to Off.

﻿

7. Ensure the following columns have been selected and added:

agent.name 
agent.type
event.code
event.action
event.dataset
event.module
log.level

8. Limit results to bp-wkstn-3. Select Add Filter.

﻿

9. In the Edit Filter area, enter agent.name to narrow the selection results. 

﻿

10. From the drop-down menu, select agent.name, as seen in Figure 27.3-3  below. 

<img width="885" height="182" alt="image" src="https://github.com/user-attachments/assets/743b94a9-1d7b-461f-978c-39321b2aaa55" />

11. From the Operator drop-down menu, select is, as seen in Figure 27.3-4 below.

<img width="920" height="219" alt="image" src="https://github.com/user-attachments/assets/902096f5-05b6-4163-8270-27ccffa709ac" />

12. In the Value field, enter bp-wkstn-3. 


13. Select Save

<img width="910" height="374" alt="image" src="https://github.com/user-attachments/assets/528bdef6-979d-43da-9b5e-ef89b2855c46" />

14. Search for the following strings to determine the timeline of operations for clearing and disabling the Windows Event Logs:
event.code: 6006
event.action: Log cleared

Use the information gathered in this workflow to respond to the following questions.

<img width="1094" height="633" alt="image" src="https://github.com/user-attachments/assets/c2ca3015-972a-451d-be1a-f06be3859e72" />
<img width="1123" height="705" alt="image" src="https://github.com/user-attachments/assets/89f4e58f-b1ce-43d2-8ac4-55e267c1357d" />

-------------

Use Logs to Find Malware Attack Paths
Based on the scenario below, complete the workflow to resume analysis of the malware attack using the VMs bp-wkstn-3 and win-hunt. 

﻿

Scenario 
﻿

After a malware attack, system and security logs on bp-wkstn-3 were deleted, and the Windows Event Log service has been disabled. These actions have led to a significant gap in the log data, creating a formidable challenge for post-incident forensic analysis. However, the attackers neglected to clear the Sysmon Operational logs during their attack. 

﻿

Enable the Windows Event Log service and conduct log analysis to determine the attack path. 


﻿

Workflow
﻿

1. Open the VM bp-wkstn-3. The login credentials are as follows:

Username: administrator
Password: CyberTraining1!
﻿

2. Open a PowerShell prompt as an Administrator and enter the following command:

MMC



3. Add the Computer Management function to the MMC console. Select File. 

﻿

4. Select Add/Remove Snap-in. 

﻿

5. Select Computer Management, and then Add. 

﻿

6. When prompted, select the Local Computer radio button, and then Finish. 

﻿

7. Enable the Windows Event Log service. Select to expand the Computer Management menu. 

﻿

8. Select to expand the Services sub-menu. 

﻿

9. Locate and right-click the Windows Event Log service, and then select Properties. 

﻿

10. For Startup Type, select Automatic, and then Apply. 

﻿

11. Select Start to start the service, then select OK. 

﻿

12. Select OK. 

﻿

If the service does not start, reboot bp-wkstn-3 and perform Steps 1-6 again.

﻿

13. Open the Sysmon Operational event log. Select to expand the System Tools menu. 

﻿

14. Select to expand the Event Viewer sub-menu, and Windows Logs. 

﻿

15. Select to expand the Applications and Services Logs sub-menu, and then Microsoft. 

﻿

16. Select to expand the Windows submenu. 


<img width="457" height="508" alt="image" src="https://github.com/user-attachments/assets/7204470d-a269-400e-931f-217a633924a9" />

17. Locate and select Sysmon. 


18. Open the Operational log.


19. Create a filter. From the Actions menu, select Filter Current Log. 


20. Select the Logged drop-down menu, and then Custom. 


21. Enter the following date information: 
From: Events On 9/21/2022 12:00:00 AM
To: Events On 9/22/2022 11:30:00 PM

<img width="675" height="288" alt="image" src="https://github.com/user-attachments/assets/fdc0d040-8632-4d87-8274-f8f0400aace1" />


22. In the Includes/Excludes Event IDs field, enter the following information: 1,11,13


<img width="805" height="463" alt="image" src="https://github.com/user-attachments/assets/27e54ad0-bba9-425e-be60-31d007a06f22" />

23. Select OK to apply the filter.


24. From the Actions menu, select Find

<img width="292" height="412" alt="image" src="https://github.com/user-attachments/assets/de1de1d1-6ddb-4d16-b62f-6eca3442f5ba" />


25. In the Search field, enter clear-eventlog.


26. Use Kibana to perform a similar search. In Kibana, set the search time frame to Sep 21, 2022 @ 00:00:00.000 to Sep 21, 2022 @ 23:30:00.000. 


27. Select Filter by Type, then set the Hide Missing Fields toggle button to Off.


28. Select and add the following columns: 
agent.name 
agent.type
event.code
event.action
event.dataset
event.module
Log.level

29. Create an agent.name filter for bp-wkstn-3, as seen in Figure 27.3-10 below.


<img width="910" height="374" alt="image" src="https://github.com/user-attachments/assets/15d474bf-6bca-41c7-8a3a-15c0bea65bd2" />

30. Enter the following query:
event.action: "Process Create (rule: processCreate)" and process.command_line: "powershell"



Figure 27.3-11 below displays the query results. 


<img width="1509" height="272" alt="image" src="https://github.com/user-attachments/assets/b3fefba7-27e8-4948-b7fc-245fe4be9083" />


Use the information collected in the workflow to answer the following question.

<img width="1145" height="687" alt="image" src="https://github.com/user-attachments/assets/3ffb4fb2-3ecf-46c8-bb0a-ff1792fe067f" />


--------------------


### CDAH-M27L4-Investigate Contained Hosts ###

 Investigative Process Overview
As discussed in earlier Cyber Defense Analyst – Host (CDA-H) lessons, the IR lifecycle consists of four phases: Preparation; Detection and Analysis; Containment, Eradication, and Recovery; and Post-Incident Activity. Figure 27.4-1 illustrates this lifecycle. This lesson focuses on investigation of contained hosts to determine an incident’s root cause and scope. Investigation is performed within the Containment portion of the third phase. 

﻿

Investigation is complete once the Recovery process of the phase begins. Upon entering Recovery, adversarial presence is eradicated and the Cyber Protection Team (CPT) should have a firm understanding of attack timelines, vectors, and other pertinent information that it submits in an After Action Report. 


<img width="2500" height="1253" alt="image" src="https://github.com/user-attachments/assets/74ff8064-c865-42c2-a031-139093b14b4e" />

Static Analysis


Static malware analysis is a basic and effective technique that allows analysts to investigate a malware sample without actually running its code. Instead, the file is examined for signs of malicious intent. Technical indicators, such as file names, hashes, Internet Protocol (IP) addresses, domains, and file header data, can be identified and evaluated. Other malware analysis tools, such as a disassembler or network analyzers, can be used to observe the malware without running it, to collect information about how the malware works in its current state. 


Dynamic Analysis


Dynamic analysis also aids analysts during the investigative process. Manual dynamic analysis involves running a file or program inside a contained environment, or sandbox, and examining it there to discover malicious content. Through the use of a VM, a snapshot of the infected host is taken at a specific point in time. Analysts use the VM snapshot to manually execute, manipulate, and experiment with the malware. The result of manual dynamic analysis is a better understanding of what the malware does, what artifacts it leaves, and how it was contracted. 


Automated static and dynamic analyses also exist and rely on software and algorithms. Although the process is efficient, automated analysis is not as thorough as manual analysis. 


This lesson uses only manual static and dynamic analyses.


<img width="1667" height="753" alt="image" src="https://github.com/user-attachments/assets/83de8b85-d276-44ba-9e57-50a5a6cb1683" />


----------------

Investigate Malware Indicators of Compromise
Read the scenario below, and complete the lab that follows. The lab includes three exercises:

Perform static and dynamic analyses on an infected host.
Investigate the C2 component.
Determine event execution to help in generating a timeline of events. 
Scenario
﻿

Security analysts identified a host within the organization that has been infected with malware. The malware is known to quickly spread among hosts on the network, especially those that have recently established connections with one another. The CPT is investigating the host sandbox, which was exposed to and infected with malware through communications within the network. The CPT has conducted initial containment operations to isolate and contain the malware. The CPT collected a snapshot of the sandbox host to allow for dynamic manual analysis. The malware varies in name but is frequently seen using folders (that may be hidden) and the registry to maintain persistence. The malware also includes a C2 component, where it attempts to send information to an external location. Table 27.4-1 presents the possible IOC associated with the malware:


<img width="882" height="2048" alt="image" src="https://github.com/user-attachments/assets/24b0e5ed-cafd-4141-9ccf-99b01dc1526a" />

-------------



Perform Analyses
A pre-investigative briefing conducted by the All-Source Analyst provided Host Analysts with critical information about the malware, indicating that its origin is from a known adversary. This adversary is known to use sleep functions that cause their malware to sleep between 30 and 120 seconds on random intervals between actions. Analysts should take this information into account when conducting dynamic analysis operations. 

﻿

Complete the steps in the following workflow to perform both static and dynamic analyses on the sandbox host, which is located in a sandbox environment. The functionality of the malware on the host is largely unknown, and although dynamic analysis is included, such unusual occurrences as connection attempts, dialog boxes, and error messages may occur. 

﻿

Prior to initiating the malware in this lab, open and set up tools for analysis, such as Process Monitor (ProcMon), Process Explorer, and Autoruns.﻿﻿

﻿

Workflow
﻿

1. Open the Virtual Machine (VM) sandbox. The login credentials are as follows:

Username: trainee
Password: CyberTraining1!
﻿

2. Open the folder C:\Users\trainee\Desktop\Malware, and double-click msg.exe to execute it. 

﻿

N﻿OTE: The malware may take a few minutes to complete its activities.

﻿


3. Conduct static and dynamic analyses of the msg.exe file by determining the processes, registry changes, and event logs changed after executing the malware executable.  

﻿

Using this workflow, answer the questions that follow.

﻿

Keep the VM sandbox open, as it is used in the next exercise.

<img width="1418" height="583" alt="image" src="https://github.com/user-attachments/assets/f689528b-0db6-407b-8fd4-0da04d7efcfc" />
<img width="1134" height="671" alt="image" src="https://github.com/user-attachments/assets/f5f20a34-cae1-4e36-9845-93d8b7023d95" />
<img width="778" height="256" alt="image" src="https://github.com/user-attachments/assets/f19865c3-96b9-427f-bcc3-08efe5096cad" />
<img width="1000" height="518" alt="image" src="https://github.com/user-attachments/assets/f97bb7c1-1775-4e44-8316-d4c4bf61184b" />
<img width="1052" height="219" alt="image" src="https://github.com/user-attachments/assets/880ae95e-9402-4eb0-bee7-9303d68cdcc5" />
<img width="1074" height="573" alt="image" src="https://github.com/user-attachments/assets/3a5f4c96-8239-4992-8d18-16c323b94fb6" />



---------------

Determine the Associated Command-and-Control Mechanism
Shift the investigation to determine the C2 mechanism associated with the malware. Investigate whether the C2 component is hard-coded into the malware, and identify any created or modified files and folders. Conduct static or dynamic analysis, as needed. 

﻿

Answer the questions that follow.
<img width="1113" height="694" alt="image" src="https://github.com/user-attachments/assets/d291d445-e3b3-42ce-b4e3-7be3781ee25e" />

<img width="1021" height="612" alt="image" src="https://github.com/user-attachments/assets/95803c70-9cb2-4d2f-ab0c-fbc5261c8e99" />

<img width="1054" height="644" alt="image" src="https://github.com/user-attachments/assets/4af30f96-308f-4e75-aca3-98a802ebd4c2" />


-------------



Determine Event Execution
Conduct static analysis of the malware-generated artifacts in C:\ProgramData\ and C:\ProgramData\SystemData folders, and also observe results from the earlier dynamic analysis, to determine event execution. This aids in developing a holistic incident timeline. 

﻿

NOTE: For this timeline investigation, the igfxCUIService process and the persistence mechanism have been disabled to preserve timestamp evidence. 

﻿

Workflow
﻿

1. Open the VM ls-wkstn-3. The login credentials are as follows:

Username: trainee
Password: CyberTraining1!
﻿

2. Review the artifacts, and answer the questions that follow.

﻿

Keep the VM ls-wkstn-3 open, as it is used in the next exercise.


<img width="1407" height="736" alt="image" src="https://github.com/user-attachments/assets/bf5a6b43-767b-446e-a356-35de3258d936" />
<img width="1160" height="705" alt="image" src="https://github.com/user-attachments/assets/46fa9658-275b-4fca-a3f0-871f0ca83897" />

-------------


Incident Response Timeline Overview
A timeline is a series of events deemed to be important and plotted on a line sequentially. Types of timeline events vary but may include when a certain process was first seen, when an email was received, or when a machine experienced a system reboot. The creation of a timeline aims to aid an investigation by providing context to the speed and scope of the infection. Timelines are created using data that includes a time and date and that is associated with a key event. Critical skills in creating a timeline are event analysis and correlation. Analysts must review, digest, and organize a large amount of data to discover the sequence of events.

﻿

Figure 27.4-3 shows a timeline of a malware infection that includes the planting and opening of a malicious document and the establishment of a C2 channel. Each event on the timeline is established by identifying and collecting an associated artifact. The associated artifact includes a timestamp that allows analysts to place the event on the timeline. 


<img width="1667" height="488" alt="image" src="https://github.com/user-attachments/assets/2948196b-c2a8-4632-97df-0f7531574df3" />


-------------


Establish Timestamps for an Incident Response Timeline
Complete the steps in the following workflow to discover timestamps associated with artifacts from an incident investigation.  

﻿

Workflow
﻿

1. Ensure that the VM ls-wkstn-3 is open. If it is not open, log in with the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Review artifacts found on the host during the investigation.

﻿

Answer the following questions.




----------------

Investigation Results
With the rapid response and identification of an IOC, the All-Source Analyst identifies the malware as the SysJoker. SysJoker malware is a recently developed, multi-platform backdoor that targets Windows, Mac, and Linux Operating Systems (OS). 

﻿

Upon further research, the CPT recommends additional mitigation strategies for Intrusion Detection Systems (IDS) or Intrusion Prevention Systems (IPS) through custom-developed detection rules. 

﻿

The CPT IR investigation resulted in the timeline shown in Figure 27.4-3 and the event correlation table shown in Table 27.4-4: 



<img width="1088" height="2048" alt="image" src="https://github.com/user-attachments/assets/55ba5d3b-e5ba-4344-a7a8-75d55dc5da74" />
