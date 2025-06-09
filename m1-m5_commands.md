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

















