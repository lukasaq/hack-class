
CDAH-M35-Hunt

hunt 9 questions

2x questions --> IOC and TTP analysis ( intel Document )


1x Question --> volatility ( 2.0 ) and kibana
 ( network activity )

 
6x Questions --> kibana

- Identify Persistence (mod3, lesson)
  (registry, schedule task, services, starup folder)

- process Exeution Analysis

  - identify schedule task (x2)
    (exculde irrelevant noise: 'and not "puppet"')
  - event log analysis
   ( windows & sysmon event codes )
  - file Share maybe 4 but dont mistake for a variable
    

--profile-Win10x64_19041


------------------------------------------

As seen in Figure 35-1 and Figure 35-2 below, run the following command to see a list of processes:
python3.7
python3.7 vol.py -f /home/trainee/Downloads/memory.dmp windows.pstree

 vol -f /home/trainee/Downloads/memory.dmp windows.pstree
<img width="1387" height="321" alt="image" src="https://github.com/user-attachments/assets/78038a0a-70bc-4e7c-999e-a90b800e76b0" />
<img width="1461" height="322" alt="image" src="https://github.com/user-attachments/assets/9a99c662-2fae-40f5-b3b0-d1146046057e" />
The powershell.exe process is a child process of Excel because it has a Parent Process Identification (PPID) of 7312.


Run windows.cmdline to see the command line, as shown in Figure 35-3 and Figure 35-4 below:

vol -h
<img width="902" height="530" alt="image" src="https://github.com/user-attachments/assets/7b87d01d-6575-4532-ab0c-228cc9c83116" />

vol -f /home/trainee/Downloads/memory.dmp windows.cmdline
<img width="1101" height="281" alt="image" src="https://github.com/user-attachments/assets/58059c52-87f8-4e44-8056-4e648e57e690" />
<img width="1883" height="452" alt="image" src="https://github.com/user-attachments/assets/397697c1-4852-402b-9f83-41e183142dd2" />

There are three powershell.exe processes with base64 encoded command lines.



-------------------

scan file for .xls because EXCEL is what started powershell.

vol -f /home/trainee/Downloads/memory.dmp windows.filescan | grep '.xls'

<img width="1124" height="214" alt="image" src="https://github.com/user-attachments/assets/f5730844-7841-4ce3-b9e0-f7386b9b0c07" />


To see which files were opened during the time of the memory capture, run the following command: 
python3.7 vol.py -f /home/trainee/Downloads/memory.dmp windows.filescan > filescan.txt



Once the filescan plugin finishes running, examine the results. 


Filter the results to the first eight characters of the Excel.exe process virtual address. Search for the common file extension associated with Excel, “xls.”


Run the following command:
cat filescan.txt |grep '0xe60e4b'|grep 'xls'



As seen in Figure 35-6 below, the results show Realestate-247PalmerSt-FinanceDetails.xlsm. 

<img width="1134" height="212" alt="image" src="https://github.com/user-attachments/assets/a595a4ce-fbfd-4fec-b669-c5d99c2252c7" />

Alternatively, use the windows.dumpfiles plugin with the Excel.exe Process Identifier (PID), and ignore files with the .dll, .exe or .ocx file extension, as seen in Figure 35-7 below. 



<img width="1438" height="568" alt="image" src="https://github.com/user-attachments/assets/2a42f794-c48f-4a2e-abd5-16a5b51416c7" />

Alternatively, use the windows.dumpfiles plugin with the Excel.exe Process Identifier (PID), and ignore files with the .dll, .exe or .ocx file extension, as seen in Figure 35-7 below. 

vol -f /home/trainee/Downloads/memory.dmp windows.dumpfiles --pid <PID>

<img width="1438" height="568" alt="image" src="https://github.com/user-attachments/assets/d34be6c9-53db-42a2-b640-bc513b1ed56a" />



The file name is discovered.

---------------

Indicator of Compromise 2 Solution
The windows.dumpfiles --virtaddr plugin will need a virtual address from the previous file scan. The file scan had multiple virtual addresses, but it is important to select the lowest address, 0xe60e4b0c8720, otherwise, the answer to this question may not be in the file. 

﻿

Run the following command, as seen in Figure 35-8 below: 

python3.7 vol.py -f /home/trainee/Downloads/memory.dmp windows.dumpfiles --virtaddr 0xe60e4b0c8720

vol -f /home/trainee/Downloads/memory.dmp windows.dumpfiles --virtaddr 0xe60e4b0c8720

<img width="1837" height="365" alt="image" src="https://github.com/user-attachments/assets/ebfdf76a-7aa4-4731-8635-adfe35e9378b" />


Run strings against the downloaded file, as seen in

strings file.0xe60e4b0c8720.0xe60e4c108450.DataSectionObject.Realestate-247PalmerSt-FinanceDetails.xlsm.dat


<img width="1828" height="294" alt="image" src="https://github.com/user-attachments/assets/e3a634e8-8e0c-4080-85c1-26d6dba996c1" />


The field HostUrl= contains the Uniform Resource Locator (URL) http://homerealtyone-fileshare.s3.amazonaws.com/Realestate-247PalmerSt-FinanceDetails.xlsm. 
 ﻿
Therefore, the domain is homerealtyone-fileshare.s3.amazonaws.co m.



--------------

Run either the windows.netscan or windows.netstat plugin. 


To run the windows.netscan plugin, enter the following command:


vol.py -f /home/trainee/Downloads/memory.dmp windows.netscan

Review the output, as seen in

<img width="1387" height="330" alt="image" src="https://github.com/user-attachments/assets/ab4c5ea1-48d9-45d8-bd6d-37f140db192d" />
<img width="1306" height="37" alt="image" src="https://github.com/user-attachments/assets/669245cc-ae86-4ef5-9841-de26aa25893c" />

Outbound communication is present between the host and two public IP addresses, 24.130.33.51 and 199.66.64.10.  


The IP 24.130.33.51 uses a non-standard port of 7171. The IP 199.66.64.10 connects over port 5044, which is common with Logstash (w inlogb eats), and is not malicious. 


--------------


Identify Additional Malware
The security team is concerned the adversary may have downloaded additional malware to aid in establishing persistence on the host.

﻿

Open the winhunt-2 VM. Using Security Onion and Elastic Stack, access Kibana to investigate the acc-win10-1 host for persistence and privilege escalation artifacts and TTPs. Start the investigation by analyzing the log files for acc-win10-1.

﻿

Previous campaigns in the industry have included additional malware such as jinex.exe, dinjo.exe, zbex.exe, finx.exe. Search for any signs of additional malware and persistence mechanisms.

﻿

In Kibana, ensure the time frame is set to April 10, 2023 @ 13:38:00.000 - April 10, 2023 @ 14:07:00.000.  

-------------------

What additional malware is found on the host?

zbex.exe 

<img width="1917" height="746" alt="image" src="https://github.com/user-attachments/assets/00423b9f-48ae-4fe4-b9d2-d91b80cca050" />


Solution


Analysis of the data contained in Elastic for each of the known malware executables confirms that .zbex.exe is the additional malware found on the acc-win10-1 host. 


The following query, as shown in Figure 35-11 below, reveals the malware present in the network:
agent.name: acc-win10-1 AND "zbex.exe"

<img width="2048" height="618" alt="image" src="https://github.com/user-attachments/assets/7de00bb0-5636-4d1a-95d2-37729360ac0f" />

As shown in Figure 35-12, zebex.exe is identifiable by analyzing the file.target field: 

<img width="1488" height="524" alt="image" src="https://github.com/user-attachments/assets/1ae4ae3e-476b-4cab-905d-d4e8cadcd8f4" />

-------------

What command was used to download additional malware? and What IP address was used to download additional malware ?

<img width="1903" height="613" alt="image" src="https://github.com/user-attachments/assets/da3a07fa-51f8-4e44-b032-f4925d73b20b" />


Identify the Command and IP Address Solution
The malware zebex.exe was downloaded using Certutil.exe from IP address 200.200.200.205. 

﻿

The following query outputs eight hits:

agent.name: acc-win10-2 AND zbex.exe
﻿

As shown in Figure 35-13, the download command is identifiable by analyzing the process.executable and process.command_line fields:

<img width="3200" height="908" alt="image" src="https://github.com/user-attachments/assets/3b47bf89-5089-4209-b2b3-35c20c117c1f" />



---------------

What registry key name is associated with additional malware ?

<img width="1900" height="499" alt="image" src="https://github.com/user-attachments/assets/51919e55-2540-440a-97b0-095b8893090e" />


Investigate Persistence 2 Solution
The malware zbex.exe was created, and it installed the SecurityForMe registry key. The registry key ensures zebex.exe runs on host boot. 

﻿

The registry key is identifiable by analyzing the Sysmon event code 13, and the winlog.event_data.TargetObject and process.executable fields.

﻿

Enter the following query to discover the registry key, as shown in Figure 35-14: 

event.code: 13 AND process.executable: "C:\Users\Administrator\zbex.exe"


<img width="2048" height="543" alt="image" src="https://github.com/user-attachments/assets/c816ae6d-4e1c-4e82-a6d2-86f41e2c6e30" />


-------------------------


Which additional tool was downloaded using certutil?

mimikatz

<img width="1911" height="498" alt="image" src="https://github.com/user-attachments/assets/850c0e6b-3016-4213-b9fb-33285812ad5c" />


Determine Privilege Escalation Techniques Solution
Mimikatz is an open-source tool used to gather credential and system information. Mimikatz is commonly used by adversaries looking to escalate privileges via credential dumping. Just like zbex.exe, mimikatz.exe was also downloaded using Certutil.exe. 

﻿

As shown in Figure 35-15 below, mimikatz.exe is identified by analyzing the file.target field:

<img width="2048" height="608" alt="image" src="https://github.com/user-attachments/assets/b652222a-33c3-4b95-ba62-9851b325b55b" />

As shown in Figure 35-16 below, enter the following query to identify how mimikatz.exe was downloaded using certutil:
agent.name: acc-win10-1 AND process.executable: "C:\Windows\system32\certutil.exe"

<img width="1612" height="578" alt="image" src="https://github.com/user-attachments/assets/72efa3d3-7109-4afe-8ede-886a70364792" />


--------------------------------------------

What process is associated with credential dumping?

lsass.exe

<img width="1918" height="612" alt="image" src="https://github.com/user-attachments/assets/f782ef19-d44b-40aa-bc48-c018172e8f8b" />


Identify Credential Dumping Solution
The credential dumping tool uses a process contained within the victim to handle the requested object. Correctly identifying credential dumping consists of an occurrence of Windows Event ID 4656 with mimikatz.exe, and an additional process.

﻿

The query event.code: 4656 displays that mimikatz.exe executed a credential dump. The process associated with the credential dump is identified by analyzing the winlog.event_data.ObjectName field. 

﻿

As shown in Figure 35-17 and Figure 35-18 below, the winlog.event_data.ObjectName field is populated with C:\Windows\System32\lsass.exe, indicating lsass.exe was used for the credential dump. 

<img width="2048" height="137" alt="image" src="https://github.com/user-attachments/assets/44520077-fb13-4b02-b50e-2bb7eed873c8" />

<img width="1622" height="472" alt="image" src="https://github.com/user-attachments/assets/2d949a28-a6cd-4857-81e1-57c18d589d43" />


--------------------


From acc-win10-1, the attacker expands to which host?

ez-dc

<img width="1905" height="619" alt="image" src="https://github.com/user-attachments/assets/73a50fad-cb17-4f53-a364-0402aef4b371" />


Identify Lateral Movement 1 Solution
After the privilege escalation and persistence attacks were executed, the attacker moved laterally around the network and performed further malicious activities. These actions can be used to identify initial lateral movement on the network. 

﻿

In Kibana, ensure the time range is set to Apr 10, 2023 13:38:00.000 - Apr 10, 2023 14:07:00.000. Initial access occurred from the identified host, acc-win10-1. Lateral movement occurs from this device. 

 ﻿

Enter the following query to filter logs for only acc-win10-1:

agent.name: acc-win10-1
﻿

Identify outgoing connections from acc-win10-1 and view hosts that have been accessed by applying the filter Destination.ip:exists.

﻿

Visualize the destination IP field in a bar graph to identify potential hosts from the local net 172.16. Ensure the number of values is set to display at least ten values of IP addresses.

﻿

Review the bar graph, seen in Figure 35-19 below, to view the hosts that are communicating with acc-win10-1.


<img width="1751" height="1136" alt="image" src="https://github.com/user-attachments/assets/326e6eb4-bbaf-4afb-89b7-eb43a8767bbd" />


On the chart, only the following four IP addresses are communicating with the host from the local network: 
172.16.2.6172.16.2.7172.16.6.255172.16.6.101
Each IP address can be investigated to identify the following details. 


The IP 172.16.6.101 is the local IP of acc-win10-1 and therefore not indicative of lateral movement. 


The IP 172.16.6.255 is the broadcast address for the network acc-win10-1 is on, and is also not indicative of lateral movement. 


The IP 172.16.2.6 is the ez-proxy host. This device is in constant communications with hosts on the network, leading to the surplus of logs, but doesn’t indicate malicious activity. 


The final IP is 172.16.2.7. This is the domain controller of the network called ez-dc. This host has communications with other hosts, and poses the greatest threat if compromised.


To further investigate this connection, return to the Discover dashboard, and add ez-dc to the initial query by IP 172.16.2.7. The resulting query is as follows:
agent.name: acc-win10-1 AND destination.ip: 172.16.2.7



Review the logs to identify details of the sc.exe process. As seen in Figure 35-20, the command was initiated from host acc-win10-1 which was then executed remotely on host ez-dc over port 135. 

<img width="1759" height="768" alt="image" src="https://github.com/user-attachments/assets/f93c82fd-c790-4857-afbc-011d4a7ff58f" />

Review the log query and notice that the query displays as the following:
sc \\ez-dc config vss binpath= "cmd.exe /c C:\Users\Public\note.exe"



This is abnormal behavior for a host on the network to use sc.exe commands to the domain controller. This illustrates the process of executing a service on ez-dc, resulting in lateral movement by the adversary.

-----------------

Which executable file is used to conduct lateral movement to ez-dc?
<img width="1903" height="628" alt="image" src="https://github.com/user-attachments/assets/88b251e5-3d9f-4a7d-b5d7-e72cd4256935" />


Identify Lateral Movement 2 Solution
The lateral movement occurred from acc-win10-1 to ez-dc. 

﻿

Begin by identifying additional behavior from acc-win10-1 prior to the remote execution on ez-dc. 

﻿

Enter the following query to find details of the remote execution:

agent.name: acc-win10-1 AND "certutil.exe"
﻿

Look for further retrieval of malware as used previously. Review the logs for the file.target field, as shown in Figure 35-21 below

<img width="2048" height="431" alt="image" src="https://github.com/user-attachments/assets/ee8126a3-8389-40ed-b124-16fcf72202ff" />

The file.target illustrates that a file called meterpreter.exe was downloaded and named as note.exe. This shows a file has been saved but does not answer that it was used for lateral movement.


Enter the following query for the actions involving this new executable file:
agent.name: acc-win10-1 AND "note.exe"



The first log in this query shows the most recent event involving note.exe on acc-win10-1, as seen in Figure 35-22 below

<img width="2048" height="687" alt="image" src="https://github.com/user-attachments/assets/49cd9613-0443-4162-9374-b4ba7cdbfcaf" />


The message details of this log shows that the command uses sc.exe to execute a command shell, which then executes the note.exe file remotely.


This type of execution is common for adversaries who want to move laterally. 


To further identify the occurrence of this activity, and filter login activity, review the logs from ez-dc. 


Enter the following query:
agent.name: ez-dc AND NOT winlog.event_id: 4624



The winlog.even_id4624 is a logon event that occurs regularly and is excluded to decrease the number of results.


Visualize the destination IP field in a bar graph. Ensure the number of values is set to display at least ten values of IP addresses, as seen in Figure 35-23 below. 


<img width="1731" height="1014" alt="image" src="https://github.com/user-attachments/assets/95034027-a3b4-41ce-a509-1089eb15dc86" />

The IP used by the attacker is seen connected to the domain controller, 24.130.33.51.


Enter the following query to filter activity from the 24.130.33.51 IP address:
agent.name: ez-dc AND "24.130.33.51"



The bottom of the logs shows the first events from this host, which can be used to identify when the remote connection was established. Comparing timestamps to the above events, we can see the file was executed at 13:58:28 and the attacker IP established a connection at 13:59.02. This shows that the remote file note.exe was executed to enable  lateral mov ement



-------------------


Detecting Malicious Executables Solution
The adversary previously used mimikatz for dumping password hashes on acc-win10-1. 

﻿

Enter the following query to validate that password dumping occurred, as seen in Figure 35-24 below:

agent.name: "ez-dc" AND "mimikatz.exe"


<img width="2048" height="235" alt="image" src="https://github.com/user-attachments/assets/fc268532-b8dd-4d24-a033-214618e64bdd" />

Mimikatz was acquired on the domain controller through these events, seen in Figure 35-24 above. In these events, the query field query: GET /mimikatz.exe can be used to identify other executables that may have been acquired in this manner.


Perform the following query to identify any acquired executables with a GET request, as seen in Figure 35-25 below:
agent.name: ez-dc AND query: GET*

<img width="2048" height="435" alt="image" src="https://github.com/user-attachments/assets/ed3b98a1-f650-471b-bdc8-aa0b093de86c" />


In this query, the GET query shows the acquisition of the meterpreter1.exe and the mimikatz.exe executables.


-------------


Identify Lateral Movement 3 Solution
Knowing the host had access to the domain controller, the entire internal network is navigable. The following steps identify the second host for lateral movement.

﻿

Enter the following query to limit the view to only logs originating from ez-dc, excluding communications to the domain controller:

agent.name: ez-dc AND NOT destination.ip: 172.16.2.7
﻿

Select the destination.ip field from the left menu and select visualize. 

﻿

Review the outgoing connections, as seen in Figure 35-26 below, to check if high numbers of communication are expected from those IP addresses.

<img width="1767" height="1053" alt="image" src="https://github.com/user-attachments/assets/f8047c30-7196-48eb-844c-bed3fe2cb3e2" />

After investigating each IP address, the following information is discovered:
The IP address 172.16.1.12 is the Domain Name System (DNS) server, and has an expected amount of communication present. The IP address 199.63.64.10 is the Security Onion server, and has an expected amount of communication present. The IP address 172.16.2.2 is the mail server, and has an expected amount of communication present. The IP address 172.16.2.255 is the broadcast IP for the local subnet, and has an expected amount of communication present. The IP address 172.16.4.107 belongs to an Information Technology (IT) Windows host, it-win10-7, and has an unusually high amount of communication present. This IP should not have significantly more logs than other devices. Further investigation of the host is required.
Enter the following query to identify logs with the new host:
agent.name: it-win10-7 AND "ez-dc"



Sixteen logs occur between these devices. Within these events is various login activity from the domain controller to the it-win10-7 host. Knowing this confirms that the domain controller was establishing a remote connection to it-win10-7 for Windows logins. 


In order to further identify if this activity occurring is due to the malicious actor on the it-win10-7 host, enter the following query:
agent.name: it-win10-7 AND NOT event.code: 4624 AND NOT event.code: 4634



This removes any login and logout activities. Perusing the log output inspecting for file.target field. This IT host is running many commands including netstat and cmd. However, at 14:04:09.813 an unusual file was executed, as seen in Figure 35-27 below:


<img width="2048" height="231" alt="image" src="https://github.com/user-attachments/assets/165215f7-7762-47f0-8717-c7ac49e2e3c3" />

The Note.exe file appears similar to the note.exe file which was executed to achieve lateral movement on the domain controller. The next log that occurred shows a domain administrator, thomas.gonzales, was logged into the device.


Inspecting further logs for execution of this process, as seen in Figure 35-28 below, the command line usage of executing cmd.exe from a service was used, which was the same as a previous lateral movement method.


<img width="1735" height="636" alt="image" src="https://github.com/user-attachments/assets/5ff42e49-a51f-4273-8c82-d1185992f618" />
This illustrates the process of executing remotely from the ez-dc system. Thus, the second lateral movement occurred from ez-dc to it-win10-7.

-------------------


Expansion Through Persistence Solution
Begin by inspecting all logs on it-win10-7 that occurred after the malware was used for lateral movement. 

﻿

Enter the following query:

agent.name: it-win10-7
﻿

Change the time frame to Apr 10, 2023 @ 14:05:01.000 - Apr 10, 2023 @ 14:07:00.000. This excludes events that occurred before the lateral movement.

 ﻿

The first log shows the adversary connecting from their host to IP 24.130.33.51, as seen in Figure 35-29 below. 


<img width="2048" height="231" alt="image" src="https://github.com/user-attachments/assets/dae43759-273f-47ee-af6c-13c76aa74e02" />



To view the command line details of all processes, visualize the field process.command_line, and ensure the graph is set to show all values in this field. When executed properly, a graph is returned, as seen in Figure 35-30 below. 


<img width="1734" height="1044" alt="image" src="https://github.com/user-attachments/assets/006efd7a-b7d7-4a20-9f28-215af3b68d3a" />

The graph shows that thirteen processes have been executed. 


Exclude any known commands used by the administrator, such as the following: 
ue-check.batfind "49998"find "LISTEN"netstat-nacmd.exe
All of these processes occurred multiple times due to the administrator running them. 


The remaining actions are shown in Figure 35-31:

<img width="1459" height="497" alt="image" src="https://github.com/user-attachments/assets/f8271fa6-0399-4e40-b201-ce477e728ec9" />

The three following processes stand out from the rest, and are of interest:
net user dexter.gordon N0tAHacker! /add net localgroup administrators dexter.gordon /addreg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControl\Set\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
The first process is a creation of a local account on the system with password N0tAHacker!. 
 ﻿
The second process shows the user was added to the administrators group. This process is alarming because it means that the attacker created a user account for persistence. 


The third process, when inspected, is used to authorize remote desktop protocol to this device. This leaves an opening for the attacker to reconnect if their primary access has been compromised. 
 ﻿
These findings show that the attacker created a local account on the system as an administrator and enabled remote desktop protocol for future access. These actions correlate to T1136.001 and T1543.003.

---------------------




















