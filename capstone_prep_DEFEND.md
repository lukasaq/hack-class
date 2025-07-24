
Investigate the Malicious File 1
Question:
﻿

What are the last five message-digest algorithm (MD5) hash characters of Rocket.exe?
﻿

(Enter the last five characters of the MD5 hash)


CFACA


Get-FileHash .\Rocket.exe -Algorithm MD5



Investigate the Malicious File 1 Solution
In Elastic, enter the following query: 

"Rocket.exe"
﻿

Analyze the winlog.event_data.Hashes field. This reveals that the MD5 hash of Rocket.exe is 9FFB4BF314BC042AFF78B63D554CFACA, as seen in Figure 38-1 below.

<img width="1358" height="385" alt="image" src="https://github.com/user-attachments/assets/8840a285-f6b8-4023-88d7-544dd8cbeda6" />


--------------


Investigate the Malicious File 2
Question:
﻿

The Rocket.exe file is in communication with which remote port?
﻿

(Enter the port number)



25997



Investigate the Malicious File 2 Solution
In Elastic, enter the following query: 

"Rocket.exe"
﻿

Analyze the destination.port field. As seen in Figure 38-2 below, the Rocket.exe file communicated with port 25997 on a remote host. 


<img width="1359" height="385" alt="image" src="https://github.com/user-attachments/assets/96fdc6fc-4461-4f92-9287-d2f6d9883cb2" />


------------


Investigate the Malicious File 3
Question:
﻿

What Internet Protocol (IP) address is in communication with the Rocket.exe file?
﻿

(Enter the IP address)


13.31.175.25


Investigate the Malicious File 3 Solution
In Elastic, enter the following query: 

"Rocket.exe"
﻿

Analyze the destination.ip field. 

﻿

As seen in Figure 38-3 below, the Rocket.exe file communicated with IP address 13.31.175.25. The IP address belongs to a remote host.


<img width="1362" height="387" alt="image" src="https://github.com/user-attachments/assets/13492fef-43d9-4b8a-ba16-ebb89f0de008" />


-----------------


The Center for Internet Security (CIS) Benchmark
Use the attached CIS Microsoft Windows 10 Enterprise Benchmark to answer the following questions and propose hardening strategies.  

he Network Access Benchmark
In Section 2.3.10 of the attached CIS Benchmark, the following recommendations related to network access are presented: 

Do not allow anonymous enumeration of Security Accounts Manager (SAM) accounts.

Do not allow storage of passwords and credentials for network authentication.

Restrict anonymous access to Named Pipes and Shares. 

Let Everyone permissions apply to anonymous users. 

Analyze the acc-win10-1 host and assess if it meets the CIS Benchmark for network access.

﻿

Question:
﻿

The host fails to meet which two CIS Benchmarks related to network access?
﻿

(Select all that apply)
<img width="666" height="230" alt="image" src="https://github.com/user-attachments/assets/a9e1e90b-ca7c-4709-aed6-3f2983f9d6cb" />


<img width="1920" height="817" alt="image" src="https://github.com/user-attachments/assets/0fe286c4-b8d2-4484-a862-4129fe8ca14c" />

The Network Access Benchmark Solution
Use the Local Group Policy Editor to review the policies in question. 

﻿

As seen in Figure 38-4 below, the following policies do not meet the CIS Benchmark:

Do not allow storage of passwords and credentials for network authentication.
Let Everyone permissions apply to anonymous users.


<img width="1550" height="306" alt="image" src="https://github.com/user-attachments/assets/8c95099d-3a19-45eb-8b1e-170b9dd041ce" />



--------------


The User Account Control Settings Benchmark
In Section 2.3.17 of the attached CIS Benchmark, the following recommendations related to User Account Control settings are presented: 

Admin Approval Mode for the Built-in Administrator.

Allow UIAccess applications to prompt for elevation without using the secure desktop.

Behavior of the elevation prompt for administrators in Admin Approval mode.

Detect application installations and prompt for elevation. 

Analyze the acc-win10-1 host and assess if it meets the CIS Benchmark for User Account Control settings.

﻿

Question:
﻿

The host fails to meet which two CIS Benchmarks related to User Account Control settings?
﻿

(Select all that apply)


<img width="714" height="236" alt="image" src="https://github.com/user-attachments/assets/ad740922-1040-4633-9bc7-253b7b1d132a" />

<img width="1917" height="834" alt="image" src="https://github.com/user-attachments/assets/ab756d4e-9d22-4a93-ae34-c7a6c9745385" />

The User Account Control Settings Benchmark Solution
Use the Local Group Policy Editor to review the policies in question.

﻿

As seen in Figure 38-5 below, the following policies do not meet the CIS Benchmark:

Admin Approval Mode for the Built-in Administrator.
Behavior of the elevation prompt for administrators in Admin Approval mode.

<img width="1680" height="198" alt="image" src="https://github.com/user-attachments/assets/cda9c459-f6f9-40e0-9606-6d0af69d2569" />



--------------


The User Rights Assignment Settings Benchmark
In Section 2.2 of the attached CIS Benchmark, the following recommendations related to User Rights Assignment settings are presented:

Allow log on through Remote Desktop Services.

Back up files and directories.

Debug programs. 

Deny access to this computer from the network.

Analyze the acc-win10-1 host and assess if it meets the CIS Benchmark for User Rights Assignment settings.

﻿

Question:
﻿

The host fails to meet which two CIS Benchmarks related to User Rights Assignment settings?
﻿

(Select all that apply)

<img width="500" height="287" alt="image" src="https://github.com/user-attachments/assets/b0232010-0e4d-4825-bdfa-632228c0c0b6" />


The User Rights Assignments Settings Benchmark Solution
Use the Local Group Policy editor to review the policies in question. 

﻿

As seen in Figure 38-6 below, the following policies do not meet the CIS Benchmark: 

Allow log on through Remote Desktop Services.
Debug programs.

<img width="2038" height="580" alt="image" src="https://github.com/user-attachments/assets/4aa0ddcd-b398-4f32-9fba-3ffa7bec9e53" />

------------------------
YARA Rule Tuning 1
Based on the analysis of acc-win10-1, propose configuration changes to harden Windows hosts and prevent future attacks.

﻿

Use the Yet Another Ridiculous Acronym (YARA) rule template,  C:\Users\Trainee\Downloads\yara\yara-rule-template.txt, to answer the following questions.  

﻿

Question:
﻿

Which conditional statement detects Rocket.exe based on the MD5 hash?
﻿

(Select the correct answer) 

yara uses lowercase

filesize > 20 KB and hash.md5(0,filesize) == "9ffb4bf314bc042aff78b63d554cfaca"


YARA Rule Tuning 1 Solution
When writing a YARA rule based on the MD5 hash of a file, the file size must be known and the hash value must be all lowercase.

﻿

As seen in Figure 38-7 below, create the following rule: 

import "hash"
rule rule1 {

	condition:
		filesize > 20KB and hash.md5(0,filesize) == "9ffb4bf314bc042aff78b63d554cfaca"
		}

<img width="1023" height="481" alt="image" src="https://github.com/user-attachments/assets/9d6f1aa8-a53c-4f61-9c81-b34960a411fe" />


The rule checks if the size of the file is larger than 20 kilobytes (KB) and has the MD5 hash value of 9ffb4bf314bc042aff78b63d554cfaca. 


Save the file as rule1.yar in the directory C:\Users\trainee\Downloads\yara. This is the directory where YARA is located.


Enter the following command in Command Prompt: 
yara64.exe -r rule1.yar Rocket.exe


--------------


YARA Rule Tuning 2
Question:
﻿
Which two methods detect files that have a Portable Executable (PE) header and match on the string "Time to dumpster dive"?
﻿

(Select all that apply)


trings: $variable = {4D 5A} $variable2 = "Time to dumpster dive" condition: all of them
• strings: $variable = "Time to dumpster dive" condition: uint16(0) == 0x5A4D and $variable


YARA Rule Tuning 2 Solution
The file header can be detected by using strings or conditional statements. 

﻿

Three rule versions are below. 

﻿

Any of the three rules can be used to detect the file based on the MZ header and the string "Time to dumpster dive". 

﻿

Enter one of the following rules in Notepad++. 

﻿

Rule Version 1
rule rule2 {
	strings:
		$string1 = "Time to dumpster dive"
		$string = "MZ"

	condition: 
		all of them
		}
﻿

Rule Version 2
rule rule2 {
	strings:
		$string1 = "Time to dumpster dive"
		$string = { 4D 5A}

	condition: 
		all of them
		}
﻿

Rule Version 3
rule rule2 {
	strings:
		$string1 = "Time to dumpster dive"

	condition: 
		uint16(0) == 0x5A4D and $string1
		}
﻿

Solution Continued 
﻿

Save the file as rule2.yar in the directory C:\Users\trainee\Downloads\yara. 

﻿

Test the rule to confirm it detects the malicious file. In Command Prompt, enter the following command:

yara64.exe rule2.yar Rocket.exe



-------------------------

YARA Rule Tuning 3
Use the rule below to answer the following question: 

rule rule3 {
	strings: 
		variable1 ="13.31.175.25"
		variable2 = "25997"
	
	condition:
		all of them and filesize > 30KB
}
﻿

Question:
﻿

Which change must be applied to the rule to detect Rocket.exe?

<img width="310" height="199" alt="image" src="https://github.com/user-attachments/assets/ddd81275-a3ae-4d27-a42d-6a5a17a00aee" />
<img width="1917" height="832" alt="image" src="https://github.com/user-attachments/assets/dc2ee103-9087-4051-b46d-11b25f18f871" />

-----------------------

YARA Rule Tuning 4
Use the rule below to answer the following question:

rule rule4 {
	strings: 
		$variable1 = "13.31.175.25"
		$variable2 = { 8B CA 44 8B C1 E8 A1 87}
	
	condition:
		all of them
}
﻿

Question:
﻿

Which hex byte value is not in Rocket.exe and must be removed for the rule to detect Rocket.exe?


87

<img width="1916" height="832" alt="image" src="https://github.com/user-attachments/assets/61d96b46-b489-454c-9568-6fba134c0e3a" />

-----------------------------------

YARA Rule Tuning 3 and 4 Solution
Rule3 Solution
﻿

The file Rocket.exe does not contain the string 25997. This can be verified by examining the strings in PowerShell. The IP address 13.31.175.25 can be found in the file, but 25997 is not. 

﻿

Obtain the file size by running the dir command in PowerShell. This reveals that the file size is 41KB, which is larger than the minimum size of 30KB in the rule. 

﻿

Removing variable2, which contains the string 25997, allows the rule to detect the Rocket.exe file.

 ﻿

Rule4 Solution 
﻿

Using HxD, open Rocket.exe. 

﻿

As seen in Figure 38-8 below, search the file for the following hex-values:

8B CA 44 8B C1 E8 A1 87

﻿

Select Search All.


<img width="406" height="292" alt="image" src="https://github.com/user-attachments/assets/af43d497-2c43-493f-8745-bd0426624fd3" />

No results are returned because the hex string is not in the Rocket.exe file. 


Remove the value 87 from the search string and search again. 


The value 87 is not present and could instead be changed to 09 to match this file. It can also be left out of the rule to match only on the first seven hex values, excluding 87.


In Notepad++, edit rule4.yar by removing the value of 87, as seen in Figure 38-9 below. 

<img width="521" height="270" alt="image" src="https://github.com/user-attachments/assets/8ae95656-14c5-43a9-bc0a-351f0b8b05fe" />




Save the file as rule4.yar in the directory C:\Users\trainee\Downloads\yara. 
 ﻿
Test the rule again. Enter the following command in Command Prompt:
yara64.exe rule4.yar Rocket.exe 

﻿-------------------------------------------------



Identify Network Connections by Host
Create a dashboard in Elastic Stack to answer the following questions without needing to conduct individual queries. 

﻿

Generate a new panel on the dashboard that shows the highest levels of traffic from individual hosts.

﻿

Question:
﻿

What is the host name of the machine that has the most network connections?
﻿

(Enter the host name, e.g., windows-pc)


ez-mail

<img width="743" height="598" alt="image" src="https://github.com/user-attachments/assets/7a6e114d-db67-48b2-a346-c5bce2f36506" />

Identify Network Connections by Host Solution
In Elastic, create a new dashboard. A new dashboard always appears blank and visualizations must be created to review traffic.

﻿

To create a visualization of the traffic by host names, select Create New Visualization. Identify the host name filter and apply it to the visualization. 

﻿

The default bar graph and settings are sufficient for this overview panel. 

﻿

As seen in Figure 38-10 below, the panel can be saved and viewed from the main dashboard


<img width="1626" height="891" alt="image" src="https://github.com/user-attachments/assets/f2d9f6f5-4224-416a-b6e3-5ae94e378c86" />




It appears that ez-dc is responsible for the most logs. However, the question is about network communications. A filter must be applied to the records to show only traffic related to network communications.


Edit the Lens and in the vertical axes apply a filter for network connections. Enter the following query:
event.dataset: network_connection



With the new filter applied, save the changes and return to the main dashboard. 


As seen in Figure 38-11 below, the dashboard shows that ez-mail is the host responsible for most network connections.

<img width="1640" height="869" alt="image" src="https://github.com/user-attachments/assets/ce003f5d-2a3d-4fb8-99e6-e99f7950ccc0" />


--------------------


Identify the Service with the Highest Traffic
On the Elastic dashboard, generate a new panel that shows the highest levels of traffic from all services.

﻿

Identify the service that produces the most traffic, and then answer the following question. 

﻿

Question:
﻿

What is the percentage of traffic of the service?
﻿

(Enter the percentage exactly as it appears in Elastic, e.g., 12.34)

51.46

<img width="1901" height="603" alt="image" src="https://github.com/user-attachments/assets/22acd725-25ad-4dff-941c-4c3f3add116b" />


-------------


Identify the Service with Highest Traffic Solution
Add a new panel to the dashboard to identify services. Within this new panel, the services on the network can be identified by the network protocols in use. 

﻿

The network.protocol field can be applied to the panel to display a graph of the top services in use. 

﻿

The resulting panel displays the total number of records per protocol in a bar graph, as seen in Figure 38-12 below.

<img width="1720" height="828" alt="image" src="https://github.com/user-attachments/assets/43b23bb0-2b0d-4e72-93de-30c57f227afb" />


To determine the percentage of each network protocol, convert the graph into a pie chart. Save the new panel to the dashboard. 


The pie chart shows the percentage of traffic for the top services on the network. 


As seen in Figure 38-13 below, the service that produces the most traffic is Domain Name System (DNS), at 51.46 percent.

<img width="1585" height="926" alt="image" src="https://github.com/user-attachments/assets/b818cd27-92bd-42e2-88bb-43dd814947ab" />


-------------


Assess Destination IP Addresses
On the Elastic dashboard, generate a new panel that shows the top traffic destinations by IP to see which hosts are receiving traffic.

﻿

Question:
﻿

What IP receives the least amount of traffic?
﻿

(Enter the details)


13.31.175.25


<img width="1920" height="669" alt="image" src="https://github.com/user-attachments/assets/91a57b5d-f4d7-40d0-8679-97290b3dbfbe" />


Assess Destination IP Addresses Solution
Create a new panel using the field destination.ip to sort traffic by receiving destinations. 

﻿

The bar graph illustrates the destinations that receive the most traffic. To see which hosts are receiving the least traffic, the horizontal axis must be organized by least traffic. This can be done by ranking direction in ascending order. 

﻿

Exclude the group Other to make the graph more readable. 

﻿

With the new filters applied, save the panel.

﻿

The panel displays the five destination IP addresses with the least traffic in the environment. 

﻿

As seen in Figure 38-14 below, the IP address 13.31.175.25 is the least targeted destination for traffic

<img width="1607" height="838" alt="image" src="https://github.com/user-attachments/assets/58dbb21c-647c-4b91-90d7-c6fb76d45d0a" />


---------------


Identify Anomalous Activity
On the Elastic dashboard, generate a new panel that shows logs of anomalies. 

﻿

Question:
﻿

What is the highest occurring anomalous activity on the organization’s network?
﻿

(Enter the log event name, e.g., invalid_connection)


DNS_RR_length_mismatch

<img width="1914" height="555" alt="image" src="https://github.com/user-attachments/assets/4a36e2d6-49cd-4106-b49a-8eb06deb521d" />

Identify Anomalous Activity Solution
A specific network category is used to label anomalous activity in the event.dataset: weird subset. 

﻿

Add a new dashboard panel. Enter the following query to filter the traffic:

event.dataset: weird
﻿

After filtering the traffic, use the filters in the left menu to identify the field that specifies names for the anomalous activity. The field is called weird.name.keyword. Use the filter to create a bar graph visualization. 

﻿

The bar graph shows the top anomalous activity occurring on the network. Save the panel and return to the dashboard.

﻿

As seen in Figure 38-15, the highest occurring anomalous activity is DNS_RR_length_mismatch



<img width="1596" height="845" alt="image" src="https://github.com/user-attachments/assets/329f732a-f001-4f51-a7ac-8733f75bb70d" />


-----------------


Analyze Firewall Policies
Review the attached RedEagle Attack Summary Intelligence Brief to determine the correct mitigation strategies for the organization.

﻿

Question:
﻿

Which two firewall rules mitigate network access?

<img width="386" height="289" alt="image" src="https://github.com/user-attachments/assets/30e1ef31-0df7-42e1-93d0-93cd36a00549" />


Analyze Firewall Policies Solution
The firewall rules are overly permissive. In order to mitigate threats, rules must be implemented to prevent unauthorized traffic.

﻿

The first rule that is explicitly annotated in the intelligence report is to block port 7007. Port 7007 was used by the threat actors to initiate connection. This port should be blocked by the firewall.

﻿

An implicit deny rule is also needed. This rule must deny traffic that does not have an explicit rule to allow the traffic. This rule adds security over the network by ensuring no unused or unauthorized services can be used to infiltrate the network. 

﻿

These rules are used to suspend any traffic that is not specified as necessary for the organization. 



------------------


Address Compromised Accounts
Question:
﻿

Which action should RedEagle perform to mitigate compromised user accounts?
﻿

(Select the correct answer)


<img width="381" height="206" alt="image" src="https://github.com/user-attachments/assets/1946b302-ea38-4aad-a527-28bc51b5d487" />


Address Compromised Accounts Solution
The brute force attack showed the results of a password attack from various accounts. Of all the accounts that were attempted to be accessed, only one showed a successful attack in the intelligence report. The accounting administrator user paulo.desmond was successfully compromised.



-----------------


Mitigate Password Attacks 1
Question:
﻿

Which policy mitigates password attacks to the organization? 
﻿

<img width="407" height="219" alt="image" src="https://github.com/user-attachments/assets/6fa8d796-4067-4cce-a890-6359175921b5" />

Mitigate Password Attacks 1 Solution
The organization's password policy indicates that it does not enforce stringent password requirements. The compromised user's password was desmond1. This password has a short length and is easily cracked by most brute force attackers.

﻿

To prevent these kinds of attacks, the organizations must implement password policies that help to mitigate these effects. This password policy should dictate that the length meets a minimum of 12 characters to ensure passwo rds are not  easily compromised by a rainbow table attack.


----------------



Mitigate Password Attacks 2
Question:
﻿

Which additional policies help mitigate password attacks to the organization? 

<img width="453" height="339" alt="image" src="https://github.com/user-attachments/assets/96e69e32-5b5a-4636-b1a0-5a0c8013c9f0" />

Mitigate Password Attacks 2 Solution
The organization's password policy indicates that it doesn’t enforce stringent password requirements. The compromised user's password was desmond1. This password includes no special characters, no uppercase characters, has a short length, and includes a word from the username. 

﻿

To prevent these kinds of attacks, the organizations must implement password policies that help to mitigate compromise. This policy must include usage of all possible characters including special characters, uppercase and lowercase letters, numeric characters, and avoidance of easily guessed words.



-----------------------------



























































































































































































































































































































































































































































