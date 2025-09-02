
how to do sigmac command 

python sigmac -t es-qs ../rules/windows/sysmon/sysmon_quarkspw_filedump.yml -c winlogbeat

if need more info refer to mod one teat review:-)



response:(7 questions)

2x Question --> linux permissions enumeration

1x question --> linux file enumeration
	(using a provided file)

2x questions network analysis
	- IP:port (what linux method used for downloading)
 	- Linux /etc/host file configuration

1x question --> identify stolen credentials

1x question --> timeline of events, question 5-6
	-modify sigmac rules
 sigmac -t es-qs <path .yml file> -c winlogbeat

---------------------------



<img width="1811" height="413" alt="image" src="https://github.com/user-attachments/assets/f6035bf5-e2dc-48c1-adc2-bc91d6f2770e" /><img width="1828" height="318" alt="image" src="https://github.com/user-attachments/assets/2fdb4154-d4f1-42d8-b90f-115c953b9b2b" />

Which two users attempted to access the UltimateFeast directory?

triston.beltran, josh.brock

<img width="1833" height="735" alt="image" src="https://github.com/user-attachments/assets/d29579b6-0251-45e0-9d76-eb79ba6475a2" />


Identify Directory Access Solution
The query event.code: 5145 and analysis of the user.name and winlog.event_data.ShareName fields reveal that josh.brock and triston.beltran attempted to access the UltimateFeast folder on the path \\EZ-FILE\UltimateFeast. 

﻿

The output of the query event.code: 5145 is shown


<img width="1293" height="457" alt="image" src="https://github.com/user-attachments/assets/625783d0-3f1e-4e91-9972-8f9b2e64f243" />


<img width="1293" height="468" alt="image" src="https://github.com/user-attachments/assets/d31a362d-3561-4b67-9a6f-3eb07a523839" />


-------------


Which Information Technology (IT) workstation was used by the compromised user accounts to access the UltimateFeast folder?

it-win10-10
<img width="1821" height="548" alt="image" src="https://github.com/user-attachments/assets/f0063219-fbae-4c9b-819e-8d8c73c08fd2" />

Investigate the Compromised Host Solution
The query event.code: 5145 and analysis of the winlog.event_data.IpAddress field reveals that 172.16.4.110 Internet Protocol (IP) address is associated with event code 5145. The IP address is also associated with access to the UltimateFeast folder. 

﻿

The output of the query event.code: 5145 is shown 

<img width="1294" height="457" alt="image" src="https://github.com/user-attachments/assets/37347645-a828-44f2-a2ed-3b77d40c96b4" />
<img width="1293" height="466" alt="image" src="https://github.com/user-attachments/assets/99167551-64cf-4469-8ef8-4bf19fb24eb6" />


To find the IT workstation associated with the 172.16.4.110 IP address, enter the following query: 
source.ip: 172.16.4.110 and user.name: triston.beltran OR user.name: josh.brock



Analysis of the agent.hostname field reveals that the 172.16.4.110 IP address is associated with the it-win10-10 workstation.


The output of the query is shown

<img width="2048" height="790" alt="image" src="https://github.com/user-attachments/assets/bcc6eed3-1de0-45b5-a30e-bbe761d6a217" />
<img width="2048" height="786" alt="image" src="https://github.com/user-attachments/assets/a34c5d09-de21-4748-aff1-f4eac31aff3e" />


-------------

What command-line tool was used to identify the permissions of the \\EZ-FILE\UltimateFeast folder?

icacls

<img width="1826" height="571" alt="image" src="https://github.com/user-attachments/assets/deaa369e-d39a-49e1-a1ca-7c6f6277ded8" />


Viewing Permissions Solution
Enter the following query:

 "*\\EZ-FILE\UltimateFeast*" 
﻿

Analysis of the process.command_line and user.name fields reveal that the command icacls \\EZ-FILE\UltimateFeast was used by josh.brock and triston.beltran. 

﻿

The query uses a wild card by surrounding \\EZ-FILE\UltimateFeast with asterisks (*). The use of the wild card means that the query searches for any occurrences of the \\EZ-FILE\UltimateFeast path. 

﻿

Reviewing the process.command_line field reveals the icacls process, which is a tool for identifying folder and file permissions. 

﻿

The output of the icacls \\EZ-FILE\UltimateFeast query is shown 

<img width="1291" height="493" alt="image" src="https://github.com/user-attachments/assets/027344a9-d545-4642-94a3-9d5db916d1df" />


The icacls command was first used by josh.brock to view the permissions related to the UltimateF east fold er. The attacker then switched to triston.beltran, which is an account with the proper permissions to access the folder


----------------

Identify Exfiltration
Exclude .inf and .ini files when answering the following question.

﻿

EZ-FILE’s IP address is 172.16.2.3, and the attacker’s hostname is it-win10-10 with an IP address of 172.16.4.110.﻿

﻿

Question:
﻿

Which two files were accessed from the \\EZ-FILE\UltimateFeast folder by the it-win10-10 host?

UltimateFeast1.txt, UltimateFeast2.txt

<img width="1837" height="697" alt="image" src="https://github.com/user-attachments/assets/fa0dc96b-f79a-4587-b53c-b48c3b537d6d" />



Enter the following query:
winlog.event_data.ShareName: "\\*\UltimateFeast"



The output of the query is seen in Figure 36-8 below. 


<img width="1399" height="544" alt="image" src="https://github.com/user-attachments/assets/cf676d9b-d1d6-419f-b639-bab9fece3531" />

The winlog.event_data.RelativeTargetName field reveals that the files UltimateFeast1.txt and UltimateFeast2.txt were accessed by the it-win-10-10 host. These files were accessed from the ez-file host. 


Additionally, searching for (agent.name:"acc-win10-10" OR agent.name:ez-file) AND "UltimateFeast" returns all results from both Zeek and the Windows event log.


---------------------------


Identify Damage
New evidence was discovered that the threat actor had moved to another host in the network. The hostname is coderepo-dev. Based on the hostname, it is possible the threat actor’s goal is to steal sensitive source code from the organization. Continue the investigation to identify what activity occurred against the coderepo-dev host.﻿

﻿

Question:
﻿

Which user account did the attacker use to access the coderepo-dev host?

triston.beltran

<img width="1830" height="549" alt="image" src="https://github.com/user-attachments/assets/53b49ebb-972e-41b7-af40-00e902d096c7" />


Identify Damage Solution
Use Elasticsearch to query for logon events. This can be done in different ways based on the various fields in Elastic, but the method below is one way to find the answer.

﻿

Use the following query, as seen in Figure 36-9 below:

agent.name:"coderepo-dev" and "login"
﻿

<img width="1075" height="644" alt="image" src="https://github.com/user-attachments/assets/ae2dfb13-d400-49a4-93a5-8299b7c79118" />


---------------

Identify Deleted Files
Question:
﻿

Which two files were deleted by the attacker from the UltimateFeast directory? 
﻿

(Enter the two file names, separated by a comma, e.g., pear.doc, apple.txt)


UninstallModules.ps1, OPA.ps1


<img width="1828" height="318" alt="image" src="https://github.com/user-attachments/assets/276a58cb-1bce-4612-87db-f9372f588c04" />



Identify Deleted Files Solution
Search Elastic for event.type:deletion by entering the following query:

agent.name:"coderepo-dev" and event.type:deletion
﻿

The file.path field displays /opt/coderepo/UltimateFeast/utils/UninstallModules.ps1 and /opt/coderepo/UltimateFeast/OPA.ps1, as seen in Figure 36-10 below

<img width="1296" height="466" alt="image" src="https://github.com/user-attachments/assets/a723de90-f59e-4fbb-9fc8-b0e87d4eda20" />


------------------------

Identify the Manipulated Log File
Question:
﻿

What log file was manipulated by the attacker? 
﻿

(Enter the full file path, e.g., /opt/data/filename.log) 

/var/log/auth.log

<img width="1811" height="413" alt="image" src="https://github.com/user-attachments/assets/8a09fcf7-bf00-4a46-8180-36f39b4f1afc" />


Identify the Manipulated Log File Solution
Use Elasticsearch to query for command line actions by the user triston.beltran.

﻿

Enter the following query:

agent.name:"coderepo-dev" and "triston.beltran" and auditd.data.cmd:*log
﻿

The query results are displayed in Figure 36-11 below: 


<img width="1284" height="459" alt="image" src="https://github.com/user-attachments/assets/b569c5ad-0d42-4b96-ab41-ec2a73bb5af8" />


In an effort to avoid detection, user triston.beltran removed its name from the account name field in the /var/log/auth.log file. 


----------------------------------

Which file did the attacker download to the host?


(Enter the file name)


apache



<img width="1826" height="376" alt="image" src="https://github.com/user-attachments/assets/02a0e601-cdb2-47c5-8a4c-ac02034c3b62" />



Investigate Memory for Malware 1 Solution
Use Elastic to find network events from the coderepo-dev host.

﻿

The first step is to identify the IP address for coderepo-dev.

﻿

Enter the following query, as seen in Figure 36-12 below:

Agent.name:"coderepo-dev"
﻿

The host.ip field identifies the IP address for this host. This field can be filtered on to cleanly show the line that identifies the IP address, as seen


<img width="1286" height="485" alt="image" src="https://github.com/user-attachments/assets/a0c335a2-dfdd-466d-95d1-2bae4259e987" />



After identifying the IP, search for network-related events. The filebeat and auditbeat modules in Elastic do not record network events. They focus on file events only. 


Enter the following query:
event.category:network and client.ip:172.16.5.5 and http.uri:*



Add the http.uri filter (by type) to see the requests, as shown in Figure 36-13 below. Additional fields can be added to see all activity tied to this event.
 
<img width="1805" height="593" alt="image" src="https://github.com/user-attachments/assets/323b40bb-c4c4-4a22-994d-a21d195cc8d5" />


--------------


Malware 2
A process is associated with a port that correlates to the downloaded file. Using Volatility, identify details of this process to answer the following question.﻿

﻿

Question:
﻿

What port is coderepo-dev listening on with the associated process?

vol.py -f /home/trainee/Downloads/memory.dmp --profile LinuxUbuntu_5_4_0-146-generic_profilex64 linux_netstat
 
2023

<img width="1290" height="213" alt="image" src="https://github.com/user-attachments/assets/8bf2dd21-76e3-455d-ab73-bb01d7f71f7f" />


Investigate Memory for Malware 2 Solution
Use Volatility to examine the memory image /home/trainee/Downloads/memory.dmp. The file apache has been discovered. 

﻿

To obtain the process ID of apache, run the following command, as seen in Figure 36-14 below:

vol.py -f ~/Downloads/memory.dmp --profile=LinuxUbuntu_5_4_0-146-generic_profilex64 linux_pslist|grep apache

<img width="1621" height="168" alt="image" src="https://github.com/user-attachments/assets/7fd2fee2-63b9-4c24-8415-7fe481ef0675" />

As seen in Figure 36-15 below, run the following command to identify the network connections that are associated with the apache process:
vol.py -f ~/Downloads/memory.dmp --profile=LinuxUbuntu_5_4_0-146-generic_profilex64 linux_netstat --pid=10505


<img width="1354" height="138" alt="image" src="https://github.com/user-attachments/assets/dff41207-196a-4e40-a626-4d31091c5079" />


he coderepo-dev host is listening on port 2023 and is communicating with 24.130.33.51


-------------------------



Malware 3
Question:
﻿

What IP address was added to the hosts.allow file? 
﻿

(Enter the IP address





24.130.33.51



<img width="1301" height="121" alt="image" src="https://github.com/user-attachments/assets/65fedfb7-8c25-4a02-ab90-e7d50a4c946c" />


Investigate Memory for Malware 3 Solution
Use Elastic to search for command line events and the hosts.allow file.

﻿

Enter the following query:

agent.name:"coderepo-dev" and "hosts.allow" and auditd.data.cmd:*
﻿

As seen in Figure 36-16 below, the log section showing ALL: 24.130.33.51 indicates that the command allowed the IP authorized access to this system as a trusted host.

﻿
<img width="1464" height="549" alt="image" src="https://github.com/user-attachments/assets/0f4cccef-ff7b-4da3-bcdf-1f5c7b719da3" />




------------------------


Response Action
By evaluating the scope of the damage, analysts can assess and identify the entirety of loss in a network environment. Using information gathered thus far, identify a preliminary response action.

﻿

Question:
﻿

Which response action is recommended for the host located at IP 172.16.4.110?


Quarantine



Response Action Solution
Take previous activity into account and identify actions from the host at 172.16.4.110.

﻿

The host it-win10-10 showed initial access to an attacker. The attacker also exploited the code repository.

﻿

Using Kibana, queries can be conducted to show a multitude of malicious activities from it-win10-10 and lateral movement within the network.

﻿

The attack would have been impeded if the host had been removed from the network and placed in a secure state. In this scenario, responders must quarantine the host.


---------------------


Scoping Attack Activity
The attacker laterally moved to the internal web server. Investigate this instance of lateral movement.

﻿

Question:
﻿

Which protocol is used to establish lateral movement between it-win10-10 and ez-www?
﻿

(Enter the protocol name as it appears in the log)

ssh


<img width="1828" height="282" alt="image" src="https://github.com/user-attachments/assets/33462b07-38bb-4f80-8baf-8f21572e61df" />



Scoping Attack Activity Solution
In Kibana, filter traffic to specify the internal web server ez-www, and to identify the connection between ez-www and the host at 172.16.4.110. 

﻿

Enter the following query:

agent.name: it-win10-10 AND destination.ip: 172.16.2.5
﻿

Reviewing the logs, the connection between the host and web server is established over port 22, as seen in Figure 36-17 below.


<img width="1600" height="182" alt="image" src="https://github.com/user-attachments/assets/ff3788ac-f73c-4af5-9021-4caf0e11135a" />

Further analysis of the log contents reveals that the protocol used is Secure Shell (SSH)


-----------


Scoping Malicious Payloads
Malicious payloads must be identified in an investigation. Use Kibana to identify any files or payloads that were transferred to the web server.

﻿

Question:
﻿

What time was the first suspicious file created on ez-www?
﻿

(Enter the time in HH:MM:ss format)

11:37:29


<img width="1828" height="374" alt="image" src="https://github.com/user-attachments/assets/e980e604-c32f-4563-b093-3623a008c49d" />


Scoping Malicious Payloads Solution
Identifying malicious files loaded to ez-www can be conducted using filters to find common download techniques.

﻿

Enter the following query:

agent.name: ez-www AND event.dataset: file_create
﻿

There are 207 events returned. As seen in Figure 36-18 below, use the time bar graph to select the beginning time frame portion:


<img width="2048" height="283" alt="image" src="https://github.com/user-attachments/assets/1838d5ba-b440-4c18-8925-2075940cd935" />

Identify times by reviewing logs. Kibana shows two logs of files acquired on the system. 


Find the timestamp of the first log file in the log details, as seen in Figure 36-19 below:

<img width="557" height="43" alt="image" src="https://github.com/user-attachments/assets/ebc71b35-65f0-4b61-9060-e3cb6e77e4ce" />


-------------

Identify Malicious Files 1
Investigate the file loaded to the system. Use the file creation time to identify additional details of the file.

﻿

Question:
﻿

Which two file names are assigned to the file downloaded onto the compromised host?
﻿

(Enter the file names exactly as they appear, separated by a comma, e.g., Test.exe, file1.exe)


wannacry[1].exe, WinDefender.exe

<img width="1828" height="374" alt="image" src="https://github.com/user-attachments/assets/9a35ebad-a7f5-45fb-9cd9-e35fa29c79d0" />


Identify Malicious Files 1 Solution
Identifying files on the system can be conducted by performing a query in Kibana.

﻿

Enter the following query:

agent.name: ez-www AND certutil*
﻿

The query illustrates searches for files acquired through the certutil function. 

﻿

Incorporate the timestamp of 11:37:29 to find the two logs associated with the creation of multiple file names on the system, as seen in Figure 36-20 below:


<img width="2048" height="435" alt="image" src="https://github.com/user-attachments/assets/84adc155-ffbe-4f92-97cd-806d9517fe3d" />



-------------


Identify Malicious Files 2
The logs show two file names, and one may be alarming. Using knowledge of popular malware, identify a known function of this file.

﻿

Question:
﻿

What type of malware is the suspicious file?
﻿





<img width="1087" height="743" alt="image" src="https://github.com/user-attachments/assets/dea594d1-d2ce-45f5-88f0-bd172316c052" />


------------


Identify Malicious Files 2 Solution
When reviewing the file names, the malicious file was originally named wannacry[1].exe. This is a strong indicator of a malicious payload pertaining to a popular malware in use.

﻿

The malware WannaCry is a known ransomware attack used to encrypt a file system and demand payment to decrypt and restore the system.

---------------

Confirming Malicious Payloads
The suspected file must be validated for malicious capabilities. Investigate the file for execution and identify key details illustrating the presence of malware.

﻿

Question:
﻿

Which process running on the web server shares a similar name with the suspected malware?
﻿

(Enter the process name as it appears, e.g., !process.exe)



@WanaDecryptor@.exe


<img width="1822" height="565" alt="image" src="https://github.com/user-attachments/assets/06119ebc-658d-4bd6-9461-481d00782f7c" />

--------------


Confirming Malicious Payloads Solution
Use filters in Kibana to explore processes running on the web server.

﻿

Enter the following query to initiate the search:

agent.name: ez-www
﻿

Apply a filter by selecting Exists In from the process.command_line field on the Filter menu. The process.command_line: exists filter shows only logs that contain the process.command_line field.

﻿

To identify key processes associated with the event, create a visualization for all running command line processes on ez-www. Many versions of this file and other executables can be associated with the malware. 

﻿

However, the most used and suspicious executable is displayed in the visualization, as seen in Figure 36-21 below.


<img width="1673" height="780" alt="image" src="https://github.com/user-attachments/assets/3007a688-77bc-4a7d-a204-ab0d28c7f66b" />


The visualization shows C:\ProgramData\fytieezpeqm652\@WanaDecryptor@.exe is running on the web server




------------------------


Mitigating Activities 1 Solution
Defensive cyber operations use an established methodology for handling ransomware. 

﻿

Never interact with or pay an attacker. Manually decrypting a file system can prove to be impossible or extremely time consuming depending on the strength of the encryption. This method is ineffective in almost all scenarios.

 ﻿

Simply restoring the system would not prevent the activity from occurring again. Mitigating strategies must be implemented first. These strategies can include defensive measures, such as creating intrusion detection or prevention system rules. With these implemented, the system can be restored from a recent backup.



------------


Mitigating Activities 2
Sigma was ineffective in its current state at detecting the specific malware on the system. A Sigma rule could have been used for the discovery and initiation of response activities if properly configured. Recommend a rule in Sigma to detect the malware presence.

﻿

Question:
﻿

What Event Identification (ID) number correlates to the correct detection of the malware in a custom Sigma rule?
﻿

(Enter the Event ID number, e.g., 3002)


4688

Mitigating Activities 2 Solution
Detecting malware with Sigma requires a custom rule written in Yet Another Markup Language (YAML). In order to detect this specific instance, certain processes must be used to categorize the malware. 

﻿

Use the specific processes in the command line that contains wannacry or WanaDecryptor to create a rule.

﻿

Create the following rule:

title: WannaCry Detection Rule
description: Detection of WannaCry Ransomware and associated processes
status: new
reference: 
author: trainee
logsource: 
product: windows
	service: security
	description: 
detection:
	selection1:
		EventID: 4688
﻿

This portion of the rule can be used to identify the key processes that are created in Windows environments. All events not containing EventID: 4688 are wrong﻿.

﻿

NOTE: This Sigma rule is used in a later task to detect WannaCry.



---------------------



Mitigating Activities 3
Continuing the Sigma rule for detection, the query should also identify specific syntax for detection. This type of Sigma rule could have been used to quickly discover and initiate response activities. Recommend a rule in Sigma to detect the malware presence with a specific identification method.

﻿

Question:
﻿

Which Event query would correlate to the correct detection of the malware in a custom Sigma rule


• NewProcessName: -'*wannacry*'-'*WanaDecryptor*'

Mitigating Activities 3 Solution
Adding to the Sigma rule using EventID: 4688, the rule must further specify a trigger to a specific portion of a log associated with the malware. 

﻿

Create the following rule:

title: WannaCry Detection Rule
description: Detection of WannaCry Ransomware and associated processes
status: new
reference: 
author: trainee
logsource: 
product: windows
	service: security
	description: 
detection:
	selection1:
		EventID: 4688
		NewProcessName:
			-'*wannacry*'
-'*WanaDecryptor*'

 falsepositives:
	-Unknown
level: critical
﻿

The process query finds the event title NewProcessName. 

﻿

All others reference the wrong event title, FileCreate, and the detection for WanaDecryptor would not be effective in finding the process since it is missing special characters. 

﻿

The *wannacry*' '*WanaDecryptor*' queries include wildcards to search for all characters before and after the file name.

﻿

NOTE: This Sigma rule is used in the next module, Disrupt.



















































































































































































































































































































































