looking for users added to  groups

given
The following query looks for event codes related to user group modification for the local Administrators group:

event.code:(4728 or 4732 or 4746 or 4751 or 4756 or 4761)

outcome

![image](https://github.com/user-attachments/assets/3257e023-6767-42f2-a03e-a66e62db9c77)


event.code:1 and process.command_line.keyword~ localgroup

outcome

![image](https://github.com/user-attachments/assets/8399310b-71e9-4b30-8501-ad3f23a1375d)


my way

![image](https://github.com/user-attachments/assets/c6f2a16d-ba04-418e-993f-b6ca2739d91f)





Run a query that shows any outbound connections from DC01 by entering the following in the field connection.local.responder:
event.dataset:conn AND source.ip : 172.16.2.5 and connection.local.responder: false | groupby destination.ip

![image](https://github.com/user-attachments/assets/fac34e8c-7f9f-42f7-b386-0bed4063b938)

does the same as last 2 filters just in one

• event.dataset:conn AND connection.local.responder: false AND (source.ip : 172.16.2.5 OR source.ip 172.16.2.6) | groupby destination.ip


4. Modify the query to search for inbound traffic for one of the domain controllers:
event.dataset:conn AND destination.ip:172.16.2.5| groupby network.protocol destination.port source.ip


 Modify the query from the previous lab as follows: 

  this query displays a series of outbound DNS to 172.16.8.4. Granted, any protocol can run over any port, but since that is the DMZ DNS server, there is a low chance that it is malicious. This traffic is expected.
  
event.dataset:conn AND source.ip:172.16.2.5| groupby network.protocol destination.port

Check whether the DC02 is the only machine with this traffic to the dmz-www host by focusing the query on the dmz-www system and that port with the following query:
event.dataset:conn AND destination.ip:172.16.8.5 AND destination.port: "47150"| groupby destination.ip network.protocol

Conduct a query for all inbound and outbound traffic to the host dmz-www: 
event.dataset:conn AND (destination.ip:"172.16.8.5" OR source.ip: "172.16.8.5")| groupby destination.ip network.protocol



When using an ‘OR’ with this tool, parentheses are required with the destination/source IP address fields otherwise source.ip: 172.16.8.5 is enough to satisfy the expression since it has equal priority as the arguments next to the ‘AND’.


 Change to the appropriate directory and enter the following command to parse the file ~/Desktop/dirwalk/dirwalk_1.txt:
(trainee@dmss-kali)-[~/Desktop/dirwalk] $ python3 parser.py -w -i dirwalk_1.txt -o dirwalk_1.csv



4. Modify the object windows_parser_definitions_2 in parser.py to conform to the file dirwalk_2.txt and enter the following command to parse the directory walk:
(trainee@dmss-kali)-[~/Desktop/dirwalk] $ python3 parser.py -x -i dirwalk_2.txt -o dirwalk_2.csv



The script  analyzer.py  has the following options to analyze the output of the script  parser.py :
-i, -input_data file — input CSV file to analyze
-m, -lastDay — files modified in the last day
-b, -knownBad — files that match known a regular expression of "bad" strings
-p, -images — files with extensions matching a list of image file types
Use the script analyzer.py to analyze dirwalk_1.csv and dirwalk_2.csv and answer the following questions. The following is an example of the input you may use:
python3 analyzer.py -i dirwalk_1.csv -p




Sigmac uses the following syntax to translate a query in Elastic syntax using the Winlogbeat configuration:

python sigmac -t <language> <path to file/rule> -c <configuration>


---------------------------------------------------------------------

########## M2 L2 ############
############# Splunk Refresher ############


Common Search Commands

![image](https://github.com/user-attachments/assets/d7dc5552-5f44-4d5e-b099-1dc151bf150d)


Although both queries count the number of 4688 process creation events per host, the second query is much more efficient.


Query 1
host="cda*" | stats count by host, EventCode | where EventCode=4688



Query 2
host="cda*" | where EventCode=4688 | stats count by host, EventCode


Run the following search to return the dataset auth.log that was imported in the previous lab:
source="auth.log" host="hr-data" sourcetype="linux_secure"


Search this dataset for threats by appending the following commands to the search, as displayed in Figure 2.2-5, below:
| eval ENV=if(isnull(ENV),"na",ENV) | stats count by host, real_user, process, USER, ENV, COMMAND


![image](https://github.com/user-attachments/assets/75ec781f-99b2-4f66-b0ab-426e7a24ee04)





edit the code

![image](https://github.com/user-attachments/assets/8b75c6fb-9904-4a3d-ab47-925170f7316d)


128 <title>Events Count by User and Host</title>
131 <query>`sysmon` | stats count by User, Computer | sort - count</query>



EventID of 16. This EventID indicates that a modification has been made to the Sysmon configuration


start notepad++ C:\Users\trainee\Desktop\tools\sigma\rules\windows\sysmon\sysmon_config_modification.yml




python sigmac -t splunk -c splunk-windows ..\rules\windows\sysmon\sysmon_config_modification.yml

The Sigmac input above includes the following elements:
python instructs the computer that a Python script is about to be run.
sigmac is the Python script to run.
-t splunk instructs Sigmac that the target is Splunk.
To find out what targets (-t) are available to use with Sigmac, users can run the command python sigmac –help

-c splunk-windows instructs Sigmac to use the configuration file splunk-windows.yml to determine mappings.
To  find out what configurations (-c) are available to use with Sigmac, users can run the command dir C:\Users\trainee\Desktop\tools\sigma\tools\config

..\rules\windows\sysmon\sysmon_config_modification.yml is the path to the Sigma rule to convert.


The command to translate the rule sudo_priv_esc.yml is as follows:
python sigmac -t splunk -c splunk-linux-custom C:\Users\trainee\Desktop\tools\sudo_priv_esc.yml | clip


Update Sigma Rules


The task in step 6 is to review the results of the Splunk search from step 5 and update the Sigma rules falsepositives section to provide context for future hunts.


The search returns an event showing privilege escalation through the command find. It also brings up false-positive events showing user accounts being created. This information should be added to the falsepositives section of the rule sudo_priv_esc.yml, as follows:


title: Linux Privilege Escalation - Sudo
id: f47007b3-2042-4822-97b9-3fb0d6cf10a1
status: experimental
description: Detects potential privilege escalation using sudo.
author: SimSpace
date: 2022/03/23
references:
  - https://gtfobins.github.io
logsource:
  product: linux
  service: auth
detection:
  selection:
    command|contains: '/bin/sh'
  condition: selection
falsepositives:
  - User accounts being created.
level: high
tags:
  - attack.privilege_escalation
  - attack.t1548.003

Writing Sigma Rules


Sigma is a signature format for writing SIEM agnostic queries. Sigma is a generic rule language for log files, just like Snort is for network traffic and Yet Another Recursive Acronym (YARA) is for files. Sigma rules are written in the format YAML Ain't Markup Language (YAML). The Sigma repository includes the tool Sigmac to translate the rules into SIEM-specific query languages. The tool Uncoder.io is also available for Sigma rule translations. It is a web app provided by SOC Prime.


Figure 2.2-8, below, describes the different elements of the Sigma rule format and their requirements. It is encouraged to fill out as many fields as possible, however, not all of the fields are required. According to the Sigma documentation, the only required fields are title, logsource, detection, and condition.


![image](https://github.com/user-attachments/assets/d1c6a3f4-71ef-4c01-b883-bd947ff86daa)

------------------------------------------------------------------------------
########## M2 L3 ############
############# Options for Endpoint ############



Enter the following filter in the Kibana query bar at the top of the page to see any Beats data from eng-wkstn-1, on which Winlogbeat was installed in the previous steps:
event.module:windows_eventlog and agent.hostname:"eng-wkstn-1"


n the Kibana Discover tab, use the following filter to find all logs returned by Wazuh with the OSSEC module tag:
event.module:ossec



The following values may be used with the field wazuh.data.type to filter for specific information:
process - The system inventory collector routinely retrieves data about running processes, so process logs may reveal unrecognized processes running on a system, and specific process names may be viewed or filtered with the process.cmd (full path) or process.name fields.
port - Since the system inventory collector retrieves data about open ports, this log, along with the fields wazuh.data.port.remote_ip and wazuh.data.port.remote_port may yield information about suspicious network connections.
hotfix - Lists which Windows Update patches have been applied to the respective system.
program - Lists installed programs on the host, using the list of software in the Uninstall registry key and a query of several other locations for well-known software.


Sysmon Event ID 1: Process Creation
Sysmon Event ID 3: Network Connection
Sysmon Event ID 12: Registry value created
Sysmon Event ID 13: Registry value set
Windows Event ID 4698: A Scheduled task was created
Windows Event ID 4657: A Registry value was modified
Windows Event ID 4697: A Service was installed
Wazuh Data Type Process: Running Processes
Wazuh Data Type Port: Open Network Connections



Below are examples of filters already used, which may be helpful:


agent.name:"eng-wkstn-3" and event.code: <insert event ID>




agent.name:"eng-wkstn-3" and event.module:ossec and wazuh.data.type: <insert datatype>


########## M2 L5 ############
############# Windows Event Monitoring ############



Tcpdump also has the ability to combine these commands for a more specific output using operators "and" or "or". The following examples use these operators to combine commands from the list above.

The following are some useful commands analysts can use during a hunt:

tcpdump -D displays the list of available interfaces.
tcpdump -i eth0 displays all traffic on an interface.
tcpdump host 172.16.11.1 finds traffic going to or from the specified IP address.
tcpdump src 172.16.11.1 filters traffic by the specified source.
tcpdump dst 172.16.11.2 filters traffic by the specified destination.
tcpdump net 1.2.3.0/24 finds packets going to or from the specified network or subnet.
tcpdump port 3389 shows traffic for the specified port.
tcpdump src port 1025 shows traffic for the specified source port.


Example 1. Find traffic from a specific IP address and specific port
tcpdump src 1.2.3.4 and dst port 3389



Example 2. Filter traffic from one subnet to another
tcpdump src net 192.168.0.0/24 and (dst net 10.0.0.0/8 or 172.16.0.0/16)

Rule Options


The rest of the rule consists of options that must be written in a specific order. Changing the order changes the meaning of the rule. Rule options are enclosed by parentheses and separated by semicolons. The following is an example of a complete rule option:
alert http any any -> any any (content:"index.php"; http_uri; sid:1;)


A content modifier looks back in the rule. In the previous example of the complete rule option, the pattern "index.php" is modified to inspect the HTTP uri buffer. This example is repeated below:
alert http any any -> any any (content:"index.php"; http_uri; sid:1;)



A sticky buffer places the buffer name first. All keywords that follow it apply to that buffer. In the following example, the pattern "403 Forbidden" is inspected against the HTTP response line because it follows the keyword http_response_line:
alert http any any -> any any (http_response_line; content:"403 Forbidden"; sid:1;)

The following is an example of a full signature that comprises options with and without settings, as well as modifiers:
alert dns 172.0.0.0/24 any -> $EXTERNAL_NET 53 (msg: "GMAIL PHISHING DETECTED"; dns_query; content:"gmail.com"; nocase; isdataat:1, relative; sid:2000; rev:1;)



########## M2 L5 ############
############# Windows Event Monitoring ############

The command auditpol displays the categories and subcategories using the Windows command line. To list all subcategories, enter the following command:
auditpol /list /subcategory:*



The following command lists the current policy:
auditpol /get /category:*


Use the following command to enable this policy:
auditpol /set /Category:"User Account Management" /success:enable














4688: A new process has been created: New PowerShell commands create the following event when the subcategory Audit Process Creation is configured.
400: Engine state is changed from None to Available: Details when the PowerShell EngineState has started.
800: Pipeline execution details for command line: Write-Host Test: Details the pipeline execution information of a command executed by PowerShell.


to enable module logging, make the following changes to the registry:
HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ModuleLogging
EnableModuleLogging = 1


This enables logging for the following Event ID:
4103: Executing Pipeline


To enable script block logging, make the following changes to the registry:
HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging
EnableScriptBlockLogging = 1



This enables logging for the following Event ID:
4104: Execute a Remote Command


To enable transcription logging, make the following changes to the registry:
HKLM\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription\
EnableInvocationHeader = 1
EnableTranscripting = 1
OutputDirectory = <path_to_directory>

he TGT response reveals that the session key used for the next step is encrypted by the user's password hash.

Expected Logging
Event ID: 4768, A Kerberos authentication ticket (TGT) was requested. 
Event Type: Failure, if the request fails.


 This section is signed by the domain's Kerberos account on the DC: krbtgt.


Expected Logging
Event ID: 4768, A Kerberos authentication ticket (TGT) was requested.
Event Type: Success, when a TGT is returned.



Registry changes create the following event IDs:
4663: An attempt was made to access an object4657: A registry value was modified




The event 4768 is when a TGT is requested. There is never a situation where a TGS can be used without a TGT being requested from that system.


########## M3 L2 ############
############# Recognizing Exploitation Attempts ############

 In the search, enter the following query to filter on the known compromised IP and search for any curl commands:
source.ip:172.16.4.5 AND curl







########## M3 L3 ############
############# Recognizing Exploitation Attempts ############

Sysmon Event ID 13: Registry value set

Scheduled Tasks


There are several methods to detect persistence via scheduled tasks. Enabling Microsoft-Windows-TaskScheduler/Operational within the Windows Event logging service provides the following six Event Identifiers (ID) specifically geared toward monitoring scheduled tasks:
Event ID 106 on Windows 7, Server 2008 R2 - Scheduled task registered
Event ID 140 on Windows 7, Server 2008 R2 / 4702 on Windows 10, Server 2016 - Scheduled task updated
Event ID 141 on Windows 7, Server 2008 R2 / 4699 on Windows 10, Server 2016 - Scheduled task deleted
Event ID 4698 on Windows 10, Server 2016 - Scheduled task created
Event ID 4700 on Windows 10, Server 2016 - Scheduled task enabled
Event ID 4701 on Windows 10, Server 2016 - Scheduled task disabled



user added in linux
![image](https://github.com/user-attachments/assets/fcd5e102-89ec-411a-9f21-3921cdd0f799)


changes to run keys
![image](https://github.com/user-attachments/assets/baf484bb-3403-453f-b037-72a61a54e886)


updated to find user group also
![image](https://github.com/user-attachments/assets/94788947-0ec7-4321-8e3b-c4e2a79df1c3)


Which Auditbeat module logged modifications to /etc/profile? 
![image](https://github.com/user-attachments/assets/0c1d25a7-c44c-4db3-b086-954d733e0f05)


########## M3 L4 ############
############# Recognizing Lateral Movement ############


Run the following query to search for the ports that WinRM uses:
destination.port: (5985 or 5986)


 Run the following query to search for any processes that suggest WinRM is being used:
process.name: wsmprovhost.exe


Run the following filter to search for those two files:
file.name: (nc64.exe or srvchk.exe)


Run the following query to search for evidence of a login with explicit credentials:
event.code: 4648

ecall the following Sysmon Event IDs that may be of assistance during the investigation:
Event ID 1: ProcessCreate             
Event ID 3: NetworkConnection
Event ID 11: FileCreate
Event ID 15: FileCreateStreamHash


########## M3 L5 ############
############# Recognizing C2 and Exfiltration ############







########## M3 L5 ############
############# Recognizing C2 and Exfiltration ############



########## M4 L1 ############
############# Using the Linux Shell ############

Query the system's hostname:
$ hostname


Enumerate the running processes on kali-hunt:
$ ps aux

Open a current process list using the top command. This command is active, so it persists until the user manually quits.
$ top

Systems can have multiple network adapters. To enumerate the status of all active connections, use the command ifconfig:
$ ifconfig 


Sometimes a specific distribution version is vulnerable to a known exploit. Determine the current system version using one or both of the commands below, which display the current kernel version in different formats.
$ cat /proc/version

or
$ uname -a


Another important capability is enumerating installed packages. There are two commands depending on which distribution of Linux the system is currently running. The output of these commands is often too long to be useful inside of a terminal, and it is recommended they be logged to a text file.


For Debian-based distributions:
$ dpkg -l



For Fedora-based distributions:
# rpm -qa

########## M4 L2 ############
############# Linux File System ############


Run the following commands and review their output to determine the identity and behavior of the file named unknown. The next question refers to this step.
(trainee@kali-hunt)-[~/lab] file unknown



(trainee@kali-hunt)-[~/lab] stat unknown



(trainee@kali-hunt)-[~/lab] strings unknown



(trainee@kali-hunt)-[~/lab] readelf -a unknown



(trainee@kali-hunt)-[~/lab] ldd unknown



(trainee@kali-hunt)-[~/lab] hexdump -n 100 --canonical unknown

------------------------------------------------------------------

In a terminal window in the VM kali-hunt, analyze the following directories and examine the creation times of the files to determine which binaries were most recently added to the protected binary directories. The next question refers to this step.


/bin



/sbin



/usr/bin



/usr/sbin


how i got the answer
![image](https://github.com/user-attachments/assets/9370b047-7605-49bf-b642-0537fda727b3)

ls -lisa <file_path> | grep 2022

grep the year as for the year that the file system was modified and you see what the newest file is


ls -alt /usr/bin | less

########## M4 L3 ############
############# Linux Permissions ############

To make a file immutable, the i attribute is added. For example, to write-protect the /etc/passwd file, the command is:
sudo chattr +i /etc/passwd



To set or unset the immutable attribute sudo privileges must be used. With the immutable attribute set, the file cannot be tampered with. To edit the file, the attribute needs to be removed with the command:
sudo chattr -i /etc/passwd

-------------------------------------------------------------

Viewing File Permissions


Identify file permissions of several different files using the commands learned. 


Workflow


1. Log in to the Virtual Machine (VM) kali-hunt using the following credentials:
Username: trainee
Password: CyberTraining1! 



2. Open a terminal console.


3. Run the following code to change directories:
cd lab



4. Run the following code to view the files within the lab directory:
ls



5. Run the following code to view the file permissions and file owner of the file myfile:
ls -l myfile



This file has the permissions read, write, execute for User, read and execute for Group, and read for Other.


6. Run the following command to view the permissions for both files within the lab directory:
ls -l



7. Look at the permissions for the file project. It has read, write, and execute permissions for all three file ownership types. This is considered the least secure type of permission, and this file is considered insecure.


8. Run the following commands to create a file, and look at the default permissions for that file:
touch myfile2
ls -l myfile2



The default permissions for any newly-created files for this system are read and write for User, read for Group, and read for Other. 


9. Run the following command to change to the home/trainee/analyst directory:
cd ../analyst

------------------------------------------------------------

The command to search for world-writable files is: 
find /dir -xdev -type f -perm -0002 -ls


The command to search for an incorrectly assigned SUID bit is:
find /dir -uid 0 -perm -4000 -type f 2>/dev/null | xargs ls -la


The /dir can be replaced with the directory that should be searched. This command can also be edited to check for an incorrectly assigned SGID bit. The following command finds any SGID bits that are incorrectly assigned:
find /dir -group 0 -perm -2000 -type f 2>/dev/null | xargs ls -la

--------------------------------------

command to see files with incorrect perms in /etc

find /etc -xdev -type f -perm -0002 -ls


########## M4 L4 ############
############# Syslog and Auditlog ############

Workflow


1. Open Terminal Emulator.


2. To create a filesystem rule, enter the following command:
(trainee@kali-hunt)-[~] $ sudo auditctl -w /etc/hosts -p wa -k hosts_file_change 


To ensure the rule is in place, enter the following command:
 (trainee@kali-hunt)-[~] $ sudo auditctl -l



Step 3 returns the following output, which indicates the rule was successfully added to the Linux Audit system:
-w /etc/hosts -p wa -k hosts_file_change 



4. To ensure the rule is enforced and works as expected, navigate to the following path:
(trainee@kali-hunt)-[~] $ sudo vi /etc/hosts



5. Select i to insert text to the file. 


6. On a new line, enter the following:
New Text



7. Save the text by entering the following command:
:wq!



8. To confirm the rule is collected query the Audit log with the following command:
(trainee@kali-hunt)-[~] $ ausearch -k hosts_file_change

------------------------------------------------

![image](https://github.com/user-attachments/assets/d796aed9-e9c0-4d43-acc6-248311d5ea0a)


First Log Entry
The log entry below shows that the first log was collected at 09:02:23, with a client IP address of 71.55.82.68.

﻿

71.55.82.68 - - [28/Feb/2022:09:02:23 +0100] "GET /student/vcityu-login.php HTTP/1.1" 200 1568 "-"
﻿
![image](https://github.com/user-attachments/assets/27feccbd-430e-4d64-ba18-8c2cd3330dd2)

![image](https://github.com/user-attachments/assets/dd33d93e-8bdd-42fb-82e4-01776a988b0e)

the correct username


the following text helps answerer the next question in the following SS

Attack Analysis
The logs contain information regarding a malicious attack to the vCityU web server. It was determined that the file r57.php is malicious and associated with the attack. The file likely included a large amount of bytes to upload to the server. Using this information, answer the next set of questions.


![image](https://github.com/user-attachments/assets/267ba4af-dd8f-43cf-8c84-abba7210bc69)


Bytes Uploaded
The following log entry contains 12459 bytes sent. The large number of bytes relative to the other logs, paired with its location, prior to any log containing r57.php, indicates this is likely the log of the malicious file upload.

﻿

71.55.82.68 - - [28/Feb/2022:09:05:41 +0100] "GET /vcity/student/plugin-install.php HTTP/1.1" 200 12459 "http://www.vcityu.com/victyu/student/plugin-install.php?tab=upload"

--------------------------------------------------------------------

![image](https://github.com/user-attachments/assets/90a76d67-5c91-4f99-80a9-fa138620cb83)

![image](https://github.com/user-attachments/assets/075d4a27-9953-4d69-a5bf-227f2eb49eaf)

yellow is correct and orange is not correct  showed up before just not how i expected it to.

First Occurrence
The following log entry includes the first occurrence of r57.php:

﻿

71.55.82.68 - - [28/Feb/2022:09:10:563 +0100] "GET /vcityu/student/admin-ajax.php?action=connector&cmd=upload&target=l1_d3AtY29udGVudA&name%5B%5D=r57.php&FILES=&_=1460873968131 HTTP/1.1" 200 731 "http://www.vcityu.com/victyu/student/admin.php?page=file-manager_settings"
﻿

Summary
﻿

All logs are different, so the CPT reviews syntax, fields, and descriptions prior to analysis. By using the vCityU apache web server logs, the CPT identifies relevant information to an investigation. They determine the timing of the logs, the client IP address, a nd the time the first occurrence of the malicious file, r57.php, was note d. 


########## M5 L1 ############
############# Linux Internals ############


View all running processes on the system in hierarchical order, one page at a time, by entering the following command:
(trainee@dmss-kali)-[~] $ ps -ejH | less



NOTE: In Linux, the command less is used to display the content of a file or the output of a command, one page at a time. To navigate the pages, use the up and down arrow keys. Enter q to exit after using this command to continue working in the terminal. 


4. Search for any instance of telnet in the process name by entering the following command:
(trainee@dmss-kali)-[~] $ ps -aux | grep 'telnet'



Analysts can use the command from step 5 to find the PID for a specific process name. In this case, they would replace telnet with the suspicious process name.


5. Output a dynamic, real-time view of all the running processes on a system by entering the following command:
(trainee@dmss-kali)-[~] $ top



The processes in the top dashboard can be sorted by different values. 


6. Enter the keys shift and N together to sort by PID. 


7. Enter q to exit the top utility.


8. Display all processes opened by a specific user and the command and filename they belong to by running the following command:
(trainee@dmss-kali)-[~] $ lsof -u trainee | less



9. Search for processes that are still locked on a system (even after being deleted) by entering the following command:
(trainee@dmss-kali)-[~] $ lsof | grep deleted



10. Display all files within the directory /proc by entering the following command: 
(trainee@dmss-kali)-[~] ls -al /proc | less



11. Display all files within the directory /proc for PID 1 by entering the following command:
(trainee@dmss-kali)-[~] ls -al /proc/1 | less



12. Display the status of a process within the directory /proc for PID 1 by entering the following command:
 (trainee@dmss-kali)-[~] cat /proc/1/status | less



This file provides the process name systemd and the process state S (sleeping). An analyst can use this file, when investigating a suspicious process, to find the process name, PID, and the state the process is in.


13. Display the command line of the process PID 1 by entering the following command:
(trainee@dmss-kali)-[~] cat /proc/1/cmdline



14. Display the executable path of the process PID 1 by entering the following command:
(trainee@dmss-kali)-[~] sudo ls -al /proc/1/exe
[sudo] password for trainee: CyberTraining1!



This file can be used when troubleshooting a process or investigating a process that is under suspicion.


15. Display a list of all of the files or devices that the process PID 1 is using by entering the following command:
(trainee@dmss-kali)-[~] sudo ls -al /proc/1/fd

-------------------------------------------------------------------------------------------

Observe Linux Host Communications
Manual Observation of Linux Host Communications
﻿

Use the networking commands from the previous section to view detailed information about the Linux system. Then, use the commands to view and observe how a Linux host communicates.

﻿

Workflow
﻿

1. Log in to the VM kali-hunt using the following credentials:

Username: trainee
Password: CyberTraining1! 
﻿

2. Open a terminal console.

﻿

3. Display the interfaces with their basic information by entering the following command:

(trainee@dmss-kali)-[~] $ ifconfig
﻿

4. Enter the command ip addr to observe the same interfaces as in step 3 and compare the differences between both commands.

﻿

When using the command ip addr, the MAC address and IP address of each interface are highlighted in color to make them easier to observe. 

﻿

5. Display the default routes for a Linux system by entering the following command:

(trainee@dmss-kali)-[~] $ ip route
﻿

6. Change the interface of eth1 to down by entering the following command:

(trainee@dmss-kali)-[~] $ sudo ip link set eth1 down
[sudo] password for trainee: CyberTraining1! 
﻿

7. Enter the command ip addr to observe the eth1 interface. 

﻿

The interface eth1 displays DOWN in red.

﻿

8. Set eth1 back to up by entering the following command:

(trainee@dmss-kali)-[~] $ sudo ip link set eth1 up
[sudo] password for trainee: CyberTraining1!
﻿

9. Search for suspicious processes on the system by entering the following command:

(trainee@dmss-kali)-[~] $ netstat -nap | less
﻿

This command displays processes from a networking point of view. This command can be used to view the file and protocol that is being used and the state that the process is in.

﻿

10. Search for any instance of the process ssh by entering the following command:

(trainee@dmss-kali)-[~] $ netstat -nap | grep 'ssh'
﻿

Netstat can also be used to search for any instance of a running process by name to determine whether it is in a listening state. This is helpful in searching for any adversaries that are listening for a specific process or port to use in an attack. In the above command, ssh can be replaced with any process or port that is unknown or suspected of being used by an adversary.

---------------------------------------------------------------------

![image](https://github.com/user-attachments/assets/1b72323a-12b8-403b-8691-a20020c86802)


![image](https://github.com/user-attachments/assets/340d2ad5-a7f1-4d51-a689-84cad4dc70f9)


![image](https://github.com/user-attachments/assets/bc88a288-5075-4422-bff1-e0c85f2832fb)


-------------------------------------------------------

########## M5 L2 ############
############# Common Linux Exploits ############



-------------------------------------------

########## M5 L3 ############
############# Persistence Mechanisms on Linux ############


Knowledge Check
Question:
﻿

What suspicious binary was made executable in /usr/local/bin?
﻿

(Enter the binary name or the absolute path to the binary)

file located in the correct file pah and using chmod to make it executable

![image](https://github.com/user-attachments/assets/0fdbfd40-c020-4b48-8bf0-5dc10943b216)


Knowledge Check
Question:
﻿

For which user was the file authorized_keys modified?
﻿
the home directory is the location for all users is so the user is JCTE even when it looks like root

![image](https://github.com/user-attachments/assets/6834a9fb-3961-4258-9aad-eec3d4d91193)


Knowledge Check
Question:
﻿

What is the name of the suspicious service that was created?

 systemctl is the commanbd to change or edit services so that is why we look for it in the query as seen below then the highlighted is the corret answer

![image](https://github.com/user-attachments/assets/fe69cf3c-1a5a-4554-b8bc-07ba3e13adaf)

querys from the previous questions

Indications of Linux Persistence
All four of the common Linux persistence methods were used in the large dataset from the previous workflow. These methods include the following:

Systemd service

SSH authorized_keys

Web shell

Binary wrapping

Systemd Service
﻿

Description
﻿

A malicious service was created called ntsh.service. It was started, enabled, and daemon-reload was run.

﻿

Query
﻿

Running the following query and then creating a table visualization to review all the process.title values reveals the suspicious process:

process.title: (*systemctl* OR *service*)
﻿

SSH Authorized Keys
﻿

Description
﻿

The root user modified /home/JCTE/.ssh/authorized_keys and /etc/ssh/sshd_config.

﻿

Query
﻿

Running the following query reveals this activity:

event.module: file_integrity AND file.path: (*.ssh/authorized_keys* OR */etc/ssh/sshd_config*)
﻿

Web Shell
﻿

Description
﻿

A suspicious php script named bdoor.php was created in /var/www/html.

﻿

Query
﻿

Running the following query reveals this activity:

process.title: */var/www/html* OR file.path: */var/www/html*
﻿

Binary Wrapping
﻿

Description
﻿

A suspicious binary named date was created in /usr/local/bin. The binary date is a standard system binary that is located in /bin by default.

﻿

Query
﻿

Running the following query reveals this activity:

process.title: */usr/local/bin* OR file.path: */usr/local/bin*

-------------------------------------------------------------


########## M5 L4 ############
############# Responding to a Linux Incident ############

Processes
The command ps -ef returns processes executed, sorted sequentially. 

﻿

Review the output of the command ps -ef.

-------------------------------------------------------------

Outlier Processes
The following line is an outlier in the output of processes executed from the command ps -ef:

﻿

root 8322  1     0  13:13  ?      00:00:000  /usr/bin/nc -l -p 17321
﻿
#**shows nc listening on port 17321**#

The line item shows that the root user accessed Netcat using the command /usr/bin/nc -l -p 17321.
 Netcat is a tool known to be leveraged for suspicious activity. The use of this process must be investigated further.

﻿

The value held by the 1 indicates that the parent process. The value 1 in the parent process defines that the process is running as a service. The services must also be investigated. 

-----------------------------------------------

Services Running
The command systemctl list-units --type=service returns services found on the host. Upon review of the services, nothing is inherited. The output does not find the association between services and process. Additional commands are needed to identify processes and their associated services.

command to see running services systemctl list-units --type=service
--------------------------------------------------------

Processes and Services
The command systemctl status | less returns processes and associated services found on the host. Query the output to discover which service is associated with the Netcat process /nc. 

--------------------------------------------------------------------

Suspicious Service
The service netlibconf.service is associated with the Netcat process found on the host. 

the previous command let us look through and find the answer
![image](https://github.com/user-attachments/assets/3d70bca3-011f-4ed3-930f-552942ec4452)


-------------------------------------------------------------------------

Suspicious Service Details
Figure 5.4-1, below, displays the output of the command systemctl status netlibconf. This command provides details associated with the service, such as the directory. 

![image](https://github.com/user-attachments/assets/9758016c-b686-49da-ae82-c308ec2c2a01)

---------------------------------------------------------

User Privileges
The command ls -la /lib/systemd/system/netlibconf.service provides the user and their permissions associated with the service. The output from the command is below:

﻿

-rw-r--r– 1 bob bob 140 Apr 21 13:09 /lib/systemd/system/netlibconf.service
﻿

This output indicates that the user bob had read and write privileges and accessed the configuration file /lib/systemd/system/netlibconf.service on April 21 at 13:09. The user bob was the only user to access the service.

﻿

Additional investigation may be necessary to definitively confirm that the file was modified by the user bob.
![image](https://github.com/user-attachments/assets/66b4bc96-0de8-478c-8d6a-df6491cb211c)

-----------------------------------------------------------------

Confirming the Incident
The command ls -ld usr/lib/systemd/system/ provides output that indicates the directory is world-writable. A world-writable directory allows any user with access to the host to write to the directory. In the incident that occurred, the user bob gained access to the host uws. Once in the host, bob created a service (netlibconf.service) and ran the process Netcat out of the service. The activity bob implemented on uws was directed with the goal of maintaining persistence on the host. 

![image](https://github.com/user-attachments/assets/132e5454-6e66-46a8-b9a0-5fad77241ced)

------------------------------------------------------------------






















