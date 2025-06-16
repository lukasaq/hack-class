########## M6 L1 ############
######### Harvesting Credentials ###########

Workflow


1. Log in to the ch-tech1 Virtual Machine (VM) using the following credentials:
Username: trainee

Password: CyberTraining1!

2. Right-click the Windows icon, and select Run. In the Open: textbox, enter PowerShell, and select OK:

Figure 6.1-2

3. Navigate to and access the Sample-Dump.txt file using the following cmdlet:
   
PS C:\Users\trainee.vcch> Get-Content C:\Users\trainee.vcch\Sample-Dump.txt



The output from the cmdlet returns eight passwords and six usernames.
![image](https://github.com/user-attachments/assets/683ffcc9-6e0d-4678-8d5f-5a21db7bac0b)

![image](https://github.com/user-attachments/assets/42803332-6534-4b28-8184-6b3577a7f4fa)

-------------------------------------------------------------------------------------------

Harvesting Credentials by Password Spraying | Part 2
Now that the credential data dump has been accessed and is viewable in the PowerShell window, a small password spraying campaign can be executed to attempt to log into the network with stolen credentials. 

NOTE: The following steps continue from the previous task.

4. Navigate to the Windows Accessories folder, and select Remote Desktop Connection.

5. In the Computer: textbox, enter ch-tech-2 and select Show Options.

![image](https://github.com/user-attachments/assets/6f7a4436-4e36-4ae7-b9c5-216c994b5f01)

![image](https://github.com/user-attachments/assets/d756785b-2dbe-42e6-bcee-9ad0d4f11e51)

6. Attempt to log into ch-tech-2 by using each password with each user name. From here, conduct a password spraying campaign to attempt to access the vcch.lan with the information provided in the Sample-Dump.txt file. A password spraying technique is often referred to as the low and slow technique, and it will take some time to conduct a campaign of this type. With password spraying, many passwords are attempted against many accounts. This means it is best to attempt to log in to every username listed with the first password before moving to the second. This practice best avoids detection and account lockout. 


A successful campaign allows access into ch-tech-2:

![image](https://github.com/user-attachments/assets/cd027d67-c8b9-41db-b7a7-6021ed3f4abe)

-------------------------------------------------------------------------------------

Protecting Credential Data from Harvesting
Walk through accessing the network's primary Domain Controller (DC) to configure and enforce strict password settings in an effort to prevent credential harvesting. 

Workflow


1. Log in to the ch-dc1 VM using the following credentials:

Username: trainee
Password: CyberTraining1!
﻿
2. The domain's password policy can be easily reviewed using PowerShell. To do so, select the Windows icon > Administrative Tools.


3. In the Administrative Tools window, select Windows PowerShell.


In the Windows PowerShell window, enter the following cmdlet:

PS C:\Users\trainee.vcch> Get-ADDefaultDomainPasswordPolicy

![image](https://github.com/user-attachments/assets/78c97562-67ec-492d-8ef2-6d55fe33508c)

----------------------------------------------------------------------

![image](https://github.com/user-attachments/assets/a7aa43d2-46ae-4db1-9db2-98cbea60323c)


-----------------------------------------------------------

![image](https://github.com/user-attachments/assets/6583d4ca-274c-4047-85ee-8503d082b986)

-------------------------------------------------------------

########## M6 L2 ############
######### Identifying Hosts and Services ###########


Workflow


1. Log in to the kali-hunt Virtual Machine (VM) using the following credentials:
Username: trainee
Password: CyberTraining1!



2. Netcat comes on several distributions, but it may not always be installed on yours. Open a terminal window and run the following command to verify that Netcat is installed on the machine:
(trainee@dmss-kali)-[~] $ which nc


![image](https://github.com/user-attachments/assets/0af9a092-1a63-47ac-ac23-6822e38e6298)


Netcat is present on the system and located in /usr/bin/nc.


3. Run the following command to view the available options available for the utility:
(trainee@dmss-kali)-[~] $ nc -h


![image](https://github.com/user-attachments/assets/69293043-1f65-499a-998a-98f6e0285d4e)


The options used in the next step are -n, -v, and -w.


4. Run the following command to scan a host in the range's DMZ network:
(trainee@dmss-kali)-[~] $ nc -nvw 10 172.35.3.6 80



The complete command is explained as follows:
-n: Do not perform any lookups of addresses, hostnames, or ports
-v: Increase verbosity
-w: Set a timeout. In this case, Netcat waits 10 seconds before giving up attempting to establish a connection.

The host being scanned is 172.35.3.6, whose primary function is as a web server.


The port being scanned is 80 or HTTP.

![image](https://github.com/user-attachments/assets/d2d381a0-bd97-4d37-a8f0-89a09438ed82)

Notice that upon connection, the client hangs. At this point in time, the TCP connection has been established and the client can send and receive data, if desired. The takeaway from this action, however, is that the port is open.


5. Select CTRL+C to close the connection.


At times, the CDA may want to scan multiple ports at once. This is where the -z option comes in handy. -z indicates that Netcat sends zero data; it simply establishes the TCP handshake, and closes the connection automatically, if it can be established. This is preferable to the alternative of selecting CTRL+C after every port.


The nc command also takes multiple ports or port ranges to check various services on a host. For example, the following are valid syntaxes:
nc -nvz 8.8.8.8 20-25       #Scans ports 20, 21, 22, 23, 24, and 25
nc -nvz 8.8.8.8 22 23 80    #Scans ports 22, 23, and 80
nc -nvz 8.8.8.8 20-25 80    #Scans ports 20, 21, 21, 23, 24, 25, and 80



6. Run the following command to test if Secure Shell (SSH), TELNET, Simple Mail Transfer Protocol (SMTP), HTTP, HTTP Secure (HTTPS), and Post Office Protocol 3 (POP3) are open:
(trainee@dmss-kali)-[~] $ nc -nvz -w 10 172.35.1.21 22 23 25 80 443 110



In this case, the host being scanned is the core router in the range network.


NOTE: Netcat only prints outputs for ports that are open. All output can be seen by running the following command:
(trainee@dmss-kali)-[~] $ for port in 22 23 25 80 443 110; do nc -nvz -w 10 172.35.1.21 $port; done

![image](https://github.com/user-attachments/assets/5606388d-0419-4ea9-88ed-16e33655addc)


----------------------------------------------------------------------------------------------

ort Scanning and Banner Grabbing with Netcat
The resulting output from the previous command is shown below:


![image](https://github.com/user-attachments/assets/93217757-f710-4c55-aeb1-20d398028f49)


As detailed, SSH is open on this device. Now that the open port is verified, perform a banner grab to get more information on the service.


NOTE: The following steps continue from the previous task.


7. Run the nc command without the -z option on the open port to perform a banner grab:
(trainee@dmss-kali)-[~] $ nc -nvw 10 172.35.1.21 22



Depending on the service running or how the service is configured, the server may not always return a banner or data. This was seen in the first port scan against HTTP; even with the socket left open, the server sent no data. 

![image](https://github.com/user-attachments/assets/7f3b4864-1560-4b94-bea4-e63a2a5c04e0)


----------------------------------------------------------------------------------------

Workflow


1. Log in to the kali-hunt VM using the following credentials:
Username: trainee
Password: CyberTraining1!



At a minimum, Nmap only needs a host to run.


2. Run the following command to conduct a Nmap scan against a host.
(trainee@dmss-kali)-[~] $ nmap 172.35.3.6


![image](https://github.com/user-attachments/assets/463aba45-3efc-47fb-9f5b-c7ebe9a8602a)



This conducts host discovery to ensure that the host is up, and conducts a scan of the 1,000 most popular TCP ports.


By default, Nmap conducts host discovery before commencing the port scan. With multiple hosts, this saves time by ensuring that a host is there before blasting thousands of packets. Nmap's default host discovery uses four packets: an ICMP echo request, a TCP probe to 80 and 443, and an ICMP Timestamp request. If the user has superuser privileges, the TCP probes are a TCP ACK to port 80 and TCP SYN to port 443. If the user only has regular user privileges, then the TCP probes are both SYN packets. However, many hosts have ICMP disabled and/or firewall rules in place so the default scan many not give the user the best results depending on the circumstances. While Nmap's host discovery can be tailored to better fit the environment, this is not covered in this lesson. To skip host discovery, for reasons such as the host is known to be up or due to the target environment configuration, use the option -Pn. For example, the following command implements skipping host discovery: 
(trainee@dmss-kali)-[~] $ nmap -Pn 8.8.8.8



NOTE: Superuser privileges are required whenever crafting raw packets as it requires lower level access, e.g., a stray ACK in the case of Nmap's host discovery.


Depending on the user privileges, the scan is a TCP SYN Stealth scan as a superuser or a TCP Connect scan as a regular user. A TCP SYN Stealth scan sends a SYN, and if it receives a SYN/ACK, it replies with a RST; it never completes a full connection. This is less likely to create logs, as many applications only create logs after a connection has been established. The switch for a TCP SYN Stealth scan is -sS.
(trainee@dmss-kali)-[~] $ nmap -sS 8.8.8.8  #Must be run as root or with sudo 



A TCP Connect scan completes the TCP handshake, then closes the connection. No special privileges are required to run this type of scan. The switch for a Full Connect scan is -sT. The following Nmap command is an example of a TCP Connect scan:
(trainee@dmss-kali)-[~] $ nmap -sT 8.8.8.8



Nmap also allows the user to specify ports, if desired, with the -p option. Listed below are some examples of valid syntax with the -p option:
nmap -sS 8.8.8.8 -p 22			#Scan port 22
nmap -sS 8.8.8.8 -p 1-100		#Scan ports 1-100
nmap -sS 8.8.8.8 -p 5,6,7,8,9	#Scan ports 5,6,7,8,9
nmap -sS 8.8.8.8 -p-			#Scan all 65,535 ports
nmap -sS 8.8.8.8 -p-25			#Scan all ports up to 25
nmap -sS 8.8.8.8 -p65530-		#Scan all ports above port 65530

![image](https://github.com/user-attachments/assets/8702780b-b64e-47ae-aaf2-fcc6c6b926e5)


----------------------------------------------------------------------------------------------------------------


Workflow


NOTE: The following steps continue from the previous task.


3. In the kali-hunt VM, run the following command to enable service, version and OS detection on a host. The host in this command is the DNS server for the range network. The sudo command prompts for a password — CyberTraining1!
(trainee@dmss-kali)-[~] $ sudo nmap -sS -sV -O -Pn 172.35.3.2 


![image](https://github.com/user-attachments/assets/a5ab0af4-f025-4bc5-9272-1341006c4128)



Based on the results of the service version and OS detection, attempt to correlate publicly or privately known exploits to gain access. For example, since the DNS service was detected as Simple DNS Plus, use open-source research to determine if there are known exploits against that service. Finding exploits is covered in a future module.


--------------------------------------------------------------

Workflow


NOTE: The following steps continue from the previous task.


4. Start a packet capture to observe the traffic being sent to the host to scan. The host in this case is 172.35.3.6, which is a web server within the range network.
(trainee@dmss-kali)-[~] $ sudo tcpdump -i eth1 -nnn 'host 172.35.3.7'

![image](https://github.com/user-attachments/assets/06790e54-8471-4b88-89f1-2769487a251d)

5. In a new window, run the following command to initiate a SYN Stealth scan against a web server host in the range network.
(trainee@dmss-kali)-[~] $ sudo nmap -sS -Pn 172.35.3.7

![image](https://github.com/user-attachments/assets/6f3454fd-c42e-482e-9368-ac3b98484951)

The packets can be seen leaving the kali host.

![image](https://github.com/user-attachments/assets/d3e06f10-5070-4a0a-8690-34090f1d47fe)


However, when the scan completes, it appears as if there is a firewall along the path to the device that is filtering traffic. Observe the packet capture. No response is ever generated from the host being scanned, so Nmap assumes that the host is filtered. Note that with the -Pn option, Nmap assumes a host is filtered if the host is not up.

![image](https://github.com/user-attachments/assets/bf919108-c657-408d-b0dc-16a0eaed9a2a)

6. Run an ACK Scan to check if the firewall is stateless. To save time, only one port is scanned, which in this case, is 22.
(trainee@dmss-kali)-[~] $ sudo nmap -sA -Pn -p 22 172.35.3.7


![image](https://github.com/user-attachments/assets/0cb6040c-5834-40d2-a2d7-a96eacdfa9fa)

Nmap reports this port as unfiltered. Observing the packet capture in the other window, it becomes evident why. This time, an RST response is received from the host.

![image](https://github.com/user-attachments/assets/6accdb8f-0290-4e99-a1cb-62da6a580485)

When a stateless firewall is found, the analyst can typically proceed with the other scans (i.e., NULL, FIN, XMAS). However, due to the underlying OSs within the range environment, the scans do not report accurate port state information. This is very common, as many modern OSs do not respond at all to these scans. 


7. Select CTRL+C to stop the tcpdump capture.

--------------------------------------------------------------

Workflow


NOTE: The following steps continue from the previous task.


8. The host to investigate is a DNS server for the range network. Run the following command to scan the top 1,000 UDP ports:
(trainee@dmss-kali)-[~] $ sudo nmap -Pn -sU 172.35.3.2

![image](https://github.com/user-attachments/assets/0fb89d4c-7b91-480c-ad6a-96a9189b3e8b)

From the scan results, it appears that UDP port 53 is open, which corresponds to the DNS service.


NOTE: Nmap reports 999 other ports as open|filtered. Recall that this is due to UDP services not having a handshake as TCP services does, and is much more difficult to get a definitive state for.

------------------------------------------------------------

Workflow


NOTE: The steps continue from the previous task.


9. Run the following command to run a port scan for the range 20-25 with the aggressive timing template. This gives some idea of the time it takes to complete the scan.
(trainee@dmss-kali)-[~] $ sudo nmap -sS -Pn -T4 -p 20-25 172.35.3.1

![image](https://github.com/user-attachments/assets/041f297c-4c20-428a-946c-71f463a34faa)

The scan completes in 13.31 seconds for six ports on one host. Runtimes may differ slightly. 


10. Run the same command, only with the sneaky timing template (T1).
(trainee@dmss-kali)-[~] $ sudo nmap -sS -Pn -T1 -p 20-25 172.35.3.1



This may take a few minutes to run.


![image](https://github.com/user-attachments/assets/9410fba4-0680-48da-bdf1-2132dd408e1f)

Note the time difference between the two: 13 seconds versus just under two minutes for just six ports. If detection is not a concern, then finishing port scans quickly is ideal. However, based on the presence and configuration of security systems within the network, it may be necessary to take more time to scan the network to prevent tipping of IDSs/IPSs.

--------------------------------------------------------------

Fun with ACAS
ACAS is the Department of Defense's (DoD's) pick when it comes to vulnerability scanners. It is a robust, highly-configurable tool that is easy to start using. Its web interface is user friendly and intuitive. Use ACAS to conduct a vulnerability assessment.

﻿

1. Log onto the kali-hunt VM using the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Open Firefox ESR from the desktop.

![image](https://github.com/user-attachments/assets/f09598ab-aced-404d-9414-d6b7f1a5491c)


3. Select the ACAS bookmark, and enter the following credentials to log in to the web page.
Username: trainee
Password: CyberTraining1!



4. Accept the DoD Notice and Consent Banner.

![image](https://github.com/user-attachments/assets/d8590534-18e3-4a3f-af25-6ed758850f97)

5. Select New Scan.


![image](https://github.com/user-attachments/assets/64c5e815-86fa-4bf3-a774-c7dfba3c6ca8)

This displays the types of scan templates available to use.


6. Select Basic Network Scan.


The Basic Network Scan is a good choice when not much is known about the devices being scanned. In the Basic Network Scan, several options are preconfigured without allowing for changes. In scans such as the Advanced Scan, more options are available to change. For our purposes, the Basic Network Scan is a good starting point.

![image](https://github.com/user-attachments/assets/a3578f5b-2bee-423a-9bc8-4839c8e33cb8)

7. Enter the following information in the fields:
Name: Core-Services-Scan
Description: Vulnerability scan of devices in the Core Services subnet.
Folder: My Scans
Targets: 172.35.2.0/24

![image](https://github.com/user-attachments/assets/5acf643b-a516-4f83-bd82-815af9c39f76)

Figure 6.2-27


The 172.35.2.0/24 range is the subnet containing the servers in the network that provide infrastructure and core functionality such as DNS and Active Directory (AD).


ACAS has functionality to enable scheduling of preconfigured scans. This can be accessed by selecting Schedule under General. This functionality is not used in this lesson.

![image](https://github.com/user-attachments/assets/eca294d1-a1a8-448c-9ac5-3c1b50a80aa5)

The Discovery menu specifies how ACAS searches for hosts. There are limited options when using the Basic template; however, other scan templates allow more granularity. The default is used in this lab.

![image](https://github.com/user-attachments/assets/f8f351b7-ae6b-4f45-b529-777060fa29af)


The Assessment menu currently contains settings for web scans. In different scan templates in ACAS, there may be more options for different types of services. The default setting is used in this lab.

![image](https://github.com/user-attachments/assets/b7b14f6d-50fe-4be9-803e-779706a4a274)

The Report menu specifies how the output is formatted. The default setting is used in this lab.

![image](https://github.com/user-attachments/assets/3da283d7-6600-47f2-a76d-0586a7053fe4)

The Advanced menu provides timing options for this scan. Depending on the bandwidth of the network and the load of the hosts, it may be desirable to configure this to network specifications. In this case, leave the defaults.

![image](https://github.com/user-attachments/assets/cd4e1080-148e-4b8f-87d0-3767fad8305c)

8. Select Credentials > Windows, and enter the following information into the fields:
Authentication method: Password
Username: trainee
Password: CyberTraining1!
Domain: vcch.lan
Never send credentials in the clear: Enabled
Do not use NTLMv1 authentication: Enabled
Start the Remote Registry service during the scan: Disabled
Enable administrative shares during the scan: Disabled
Start the Server service during the scan: Enabled

![image](https://github.com/user-attachments/assets/c8e0dd60-0ed0-4ec5-9d6d-1b92b551f5bc)

The Plugins tab allows you to view the plugins used during the scan. With the Basic template, only the plugins used are visible. In other templates, plugins can be added or removed if information about the network is known. At this point in time, not much is known about the Core Services subnet, so the defaults are fine.

![image](https://github.com/user-attachments/assets/6af1dcea-9af2-493a-8eb9-b3bfe0888d54)




9. Select Save.


This takes the trainee to the My Scans screen.

![image](https://github.com/user-attachments/assets/d49274c3-807f-4750-a4e9-5909e5f0e49a)

10. Select the Play icon on the configured scan to begin the scan.


NOTE: This takes approximately 30 minutes to complete. Allow the scan to run in the background and continue with the next section of the lab while waiting for this to complete.

---------------------------------------------------

Workflow


NOTE: The following steps continue from the previous task.


11. Run the following command to check what ports are open on the web server in the range environment.
(trainee@dmss-kali)-[~] $ sudo nmap -sS -T4 172.35.3.6


![image](https://github.com/user-attachments/assets/f1c8a06e-05ea-4495-b82d-964b381a575a)

After determining which ports are open, the appropriate scripts can be selected. On this distribution, scripts included with Nmap are located in /usr/share/nmap/scripts.


The naming convention allows for easy searching as each script begins with the protocol or service it was intended for.


12. View which scripts are available for HTTP by running the following command:
(trainee@dmss-kali)-[~] $ ls /usr/share/nmap/scripts/http-*

![image](https://github.com/user-attachments/assets/75c5f330-29b6-4309-8434-5e8be6a23865)

Some output has been truncated. To find more information about a particular script, use the --script-help option.


13. Find out more about the first HTTP script available — http-adobe-coldfusion-apsa1301.nse — by running the following command:
(trainee@dmss-kali)-[~] $ nmap --script-help http-adobe-coldfusion-apsa1301.nse

![image](https://github.com/user-attachments/assets/91aa5d17-83e9-45a4-abc0-58ceca3737f9)


Notice the Categories line in the output. For this script, the categories are exploit and vuln. Nmap classifies their NSE scripts into different categories as listed in the attachment. This way, users can specify which category of scripts to run.


The -sC option enables the scripting engine, but to run specific scripts, use the --script option instead. The -sC option is the equivalent of --script=default. Default corresponds to the script category. 


The --script option allows for more granularity on what is run and accepts Boolean logic. For example, the string below is a valid argument for the script parameter:
--script "(http-* or postgresql-*) and (default or safe)"



This searches for scripts beginning with http or pgsql and only runs them if they are categorized as default or safe.


14. Run the following command to enable the NSE with the default scripts for each open port discovered from the previous scan:
(trainee@dmss-kali)-[~] $ sudo nmap -sC -p 80,443,5432 172.35.3.6



As shown below, NMAP was able to read the robots.txt file and examine the Transport Layer Security (TLS) certificates of the web and Postgresql server.

![image](https://github.com/user-attachments/assets/967c12a5-32df-4efe-bca3-d299b63be714)

--------------------------------------------------------------

Workflow


NOTE: The following steps continue from the previous task.


15. Run the following command to scan a web server within the range environment with Nikto:
(trainee@dmss-kali)-[~] $ nikto -h 172.35.3.6



The -h specifies the host.

![image](https://github.com/user-attachments/assets/bc56288b-1607-4f0f-b6cf-21fc15058679)

he output from the scan is as explained:


Nikto was able to identify the version of the web server, which was Nginx 1.14.0 as per the first bullet. Nikto was also able to identify issues that may lead to clickjacking and XSS, as well as a potential rendering issue that may occur on web browsers from the following three bullets. Clickjacking is when an attacker uses transparent or opaque layers over the actual content of the page to cause a user to click on the attacker's link and sends the user to a malicious page. The clickjacking issue was discovered due to a lack of the X-Frame-Options header, as referenced by the second bullet in the output. The XSS issue comes from an absent X-XSS-Protection header, as evidenced by the third bullet. The potential rendering issue is also the result of a missing header, the X-Content-Type-Options header as per the fourth bullet.


The scan took 2 minutes and 36 seconds, which is reasonably short.

---------------------------------------------------------

Workflow


NOTE: The following steps continue from the previous task.


16. Select the Vulnerabilities tab.

![image](https://github.com/user-attachments/assets/0af9245f-38da-4803-9532-7390d3139eee)

Notice that each individual vulnerability is grouped into a Family. It is possible to toggle the grouping with the gear icon, but this is not performed in this lesson.


17. Select the first Family: Microsoft Windows (Multiple Issues).


![image](https://github.com/user-attachments/assets/080d591d-878d-47a2-b3da-309fb2247d41)

This page displays a listing of vulnerabilities from most severe to least. From the scan report, one of the hosts is affected by a remote code execution vulnerability.


18. Select MS14-066 to find out more about it.

![image](https://github.com/user-attachments/assets/c6515d72-d22d-4972-b354-7d45c00082ac)

A general Description, Solution, the Plugin Details used to detect the vulnerability, Risk Information, Vulnerability Information, etc., can be found under each vulnerability.


19. Use the scan results to answer the following questions.

![image](https://github.com/user-attachments/assets/4ef9b29a-2f2a-4e8a-8f18-bdb7a68f97b1)

![image](https://github.com/user-attachments/assets/31cb388f-8996-4982-bdc5-3eb13c5004ed)

Lab Recap
Vulnerability scanners highlight the importance of keeping software updated and disabling unneeded services. In this lab, trainees experimented with the vulnerability scanners ACAS, NMAP NSE, and Nikto. Trainees are now familiar with usage of the aforementioned tools, and can now use these tools on CPT missions that may require them. 

--------------------------------------------------------------------------------

Detecting Scanners
Luckily for network defenders, port and vulnerability scanners are generally noisy. Depending on the scanning software and options selected while running, it can be easy to spot these scanning tools in traffic. Use Zeek logs to identify scanning activities in Kibana.

﻿

Workflow

﻿

1. Log in to the kali-hunt VM using the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Open Firefox ESR, and select the Security Onion bookmark.

﻿

3. Enter the following credentials when prompted.

Username: trainee@jdmss.lan
Password: CyberTraining1!
﻿

4. After successfully logging in, select Kibana from the side menu, and navigate to the Discover page.

﻿

5. Set the time range to the following: Oct 12, 2021 @ 11:30:00 - Oct 12, 2021 @ 12:00:00.

﻿

6. Enter the following query in the search bar:

event.dataset:conn
﻿

This filters for all connection logs created by Zeek. There are 6,528 results. Also, there is an obvious bump where there was a surplus of traffic. 

![image](https://github.com/user-attachments/assets/1b38d00b-4f9c-4ac2-86ed-25021a046790)



7. Toggle the following fields:
source.ip
destination.ip
destination.port
connection.state
client.packets
server.packets

![image](https://github.com/user-attachments/assets/f126c788-cc91-44f5-86a5-1cf2e49c082c)

Connection states are values defined by Zeek and are broken out as follows:

![image](https://github.com/user-attachments/assets/188d6916-4579-4021-b3cb-11042c63b544)

Typical connections end with SF.


A server with an open port scanned using a TCP Connect or SYN Stealth scan results in a connection.state with the code RSTO.


A server with a closed port scanned using a Connect or a SYN results in a REJ.


A server with a filtered port scanned using either a TCP SYN or Connect results in a state of S0.


Finally, a garbage package resulting from an ACK, FIN, Xmas, Null, Maimon, etc., scans results in OTH.


Putting this all together, a TCP Connect scan can be characterized by a single host attempting to connect to multiple ports; a short session length of only one packet (client SYN, filtered port), two packets (client SYN, server RST), or four packets(client SYN, server SYN/ACK, client ACK, client RST) between the client and the server; and a combination of S0 or REJ and SF. TCP SYN scans share many characteristics of TCP Connect scans, except the maximum amount of packets possible is three — the client SYN, the server SYN/ACK, and a following client RST.


8. Observe the connections that occurred during the traffic spike by selecting the 11:56 bar.

![image](https://github.com/user-attachments/assets/0b0bdfb2-9a9f-4933-a2a0-c6ad458e9f10)

It is evident that the host responsible for starting the scans is 199.63.64.51 after scrolling through the results and seeing several seemingly random ports with no responses. Also, ports are not opening are filtered, as indicated by the S0 connection state and no server packets. Recall that an unfiltered host returns a RST, resulting in a server.packet count of 1.

![image](https://github.com/user-attachments/assets/9a7d72f4-2578-47a0-8858-6f97836a5c40)

9. Filter for this host by running the following query:
event.dataset:conn and source.ip:199.63.64.51



To determine which type of scan it was, locate the behavior of the scan after an open port was found. This means that there are at least two client packets, the first being a SYN, and the second packet either being an ACK for a TCP Connect Scan or a RST for a SYN Stealth Scan.


10. Run the following query to check the behavior of the scanning host after an open port is detected:
event.dataset:conn and source.ip:199.63.64.51 and client.packets>=2

![image](https://github.com/user-attachments/assets/4a3d516b-5267-4032-b134-822277b5dca4)

![image](https://github.com/user-attachments/assets/70181505-b6e6-4695-98ea-6c7cc2335f40)

-------------------------------------------------------------

Workflow


NOTE: The following steps continue from the previous task.


11. Clear the current search and set the time range to October 12th, 2021 14:30 - October 12th, 2021 16:00. The columns toggled in the previous steps should still be set.

![image](https://github.com/user-attachments/assets/557ebaed-2750-4ebf-9b3b-0be75f249457)


12. Run the following query to filter for only Zeek connection logs.
event.dataset:conn

![image](https://github.com/user-attachments/assets/e25ba4b6-f5ba-45a3-ba32-30c30befdc62)

The scans are not nearly as obvious now. Recall that in the previous scan, there was a single large spike, but is not immediately noticeable here. The -T0 option was used to run this scan, which is why it blends in with the traffic much better. Luckily, there are a few methods of detecting these scans. The first method that was examined uses the behavioral characteristics of Nmap scans that were examined in previous steps. This time, search for packets generated by open AND closed ports. The purpose of this is to identify any potential port scanning behavior at all. A few port probes may be normal, but a large range of ports scanned by the same host appears more suspicious.


13. Run the following query to search for scanning behavior:
event.dataset:conn and source.ip:199.63.64.51 and ((client.packets>=1 and client.packets<=3) and server.packets<=1)



Now, the scanning becomes more apparent. 

![image](https://github.com/user-attachments/assets/41fd873d-5a98-491e-bdbd-39995b79a81a)

Scrolling through the results, there is a wide range of ports and short sessions, which points towards a port scanning attempt.


There are a few sessions with three client packets despite all being SYN packets. For all intents and purposes, they should be interpreted as their own connection.


The second detection method covered in this lesson uses Nmap's TCP options. Recall that Nmap uses TCP options to identify host OSs. Ironically, Nmap can be identified via its TCP options as well, namely its TCP Window Size. Nmap sets a default window size of 1024, which is not a typical window size. Typically, OSs have the maximum window size set, not including the scaling factor in the TCP options. This makes identification easier, as a scan can be detected in as little as a single packet. Currently, there is not an easy way to set the TCP Window Size using the Nmap utility itself without recompiling the program. Use the Suricata event module to identify Nmap scans.


14. Run the following query to filter for Suricata events:
event.module:suricata and message:NMAP

![image](https://github.com/user-attachments/assets/89d69c0d-e55a-4b5f-b3b8-49e789fda8ee)


15. Toggle the following fields:
rule.name
message

![image](https://github.com/user-attachments/assets/33d7402f-de66-45df-9406-259b9234df2c)

As the rule.name and message fields state, a possible NMAP scan was detected. The rule used simply matches on window size, with the threshold to generate an alert being 5 packets in 60 seconds, which is why the graph does not exactly match up with the previous query.

![image](https://github.com/user-attachments/assets/2b408d24-a8ce-4db5-bb0c-1ea296827c6d)


--------------------------------------

Workflow


NOTE: The following steps continue from the previous task.


16. Set the time range to the following: October 12, 2021 14:00 - October 12, 2021 15:00

![image](https://github.com/user-attachments/assets/c65f0d50-ba3d-4eda-ba0f-9465419fb45f)

17. Filter the events for Zeek connection logs:
event.dataset:conn

![image](https://github.com/user-attachments/assets/9b28332f-4cad-4275-8465-74db40932e70)

As with Nmap, there is a huge spike in traffic. However, the traffic spike lasts longer than with a Nmap scan.


18. Select the highest point of the traffic spike, which begins at 14:08. Note that the beginning of the spike starts at 14:07, which is where port scanning occurs. This largely appears the same as Nmap scanning.

![image](https://github.com/user-attachments/assets/33b3a8a5-b164-44d8-afa0-18527f740c0c)


![image](https://github.com/user-attachments/assets/d4d542d3-3134-4106-9657-efdef26e65ac)

-----------------------------------------------

etecting Nikto Scans
Examine what Nikto scans look like in traffic.

﻿

Workflow

﻿

NOTE: The following steps continue from the previous task.

﻿

19. Set the time range to the following: October 12, 2021 16:30 - October 12, 2021 17:00

﻿

Unlike the other scans examined, Nikto scans are most prominent in Zeek HTTP Logs.

﻿

20. Filter for HTTP logs by running the following query:

event.dataset:http

![image](https://github.com/user-attachments/assets/a8e9728a-a11f-40b1-bb02-dac6ac55969a)

Like the other scans, Nikto is marked by a significant uptick in traffic.


21. Select the highest peak which starts at 16:57.


22. Toggle the following fields:
source.ip
destination.ip
http.status_code
http.uri
http.request.body.length
http.response.body.length

![image](https://github.com/user-attachments/assets/fbcbd8cf-e845-44a9-895e-33500dc3f0f6)

Upon first glance, several HTTP 301s can be seen from 199.63.64.51. There are a few HTTP 404s that can be seen but may not come from 199.63.64.51.


![image](https://github.com/user-attachments/assets/13feb66d-c0ea-4ff0-b4d8-28c6716a5305)

If the source IP address was not known, then it is found by selecting the highest spike. However, this view is not much more useful as there is not much to glean, other than the excess of HTTP 301s.


23. Return the time range to October 12, 2021 16:30 - October 12, 2021 17:00, and run the following query to filter out web connections from different hosts:
event.dataset:http and source.ip:199.63.64.51

![image](https://github.com/user-attachments/assets/c7278536-97e4-4f34-b23d-3bd3478f3dd7)

After filtering for 199.63.64.51, much more spookiness is seen. First, notice the user agent string Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:007239), which not only stands out, but lets the user know exactly what program is running the vulnerability scan. While script kiddies may not know to change the user agent value, it is trivial to do so by changing the user agent string in the config file.


Because of this, relying on the user agent to identify Nikto is not always reliable. However, the behavior is used to more consistently identify scanning attempts. Note the http.uri field. Nikto attempts to brute force several config files, security-related files, account files, database files, etc. This is not normal user behavior and can be marked as related to scanning activity. A signature that could catch this might trigger an alert if three or more different Uniform Resource Identifiers (URI) from the results are requested. Nikto has built-in evasion techniques to attempt circumvention.


24. Set the time range to October 12, 2021 17:00 - October 12, 2021 17:30. Do not clear the current query or any fields.

![image](https://github.com/user-attachments/assets/380bd770-b6fb-4642-9f1e-f6d6d0e18427)

This Nikto scan used an IDS evasion technique. Scrolling through the results, it is evident that some URIs are using Uniform Resource Locator (URL) encoding, which may circumvent some signatures. URL encoding enables characters outside of the ascii range and special characters. URL uses the percent sign (%) and hexadecimal to encode characters, e.g. a space is encoded as %20. to be transmitted over the Internet. In the data, we can see a %27, which is the ' character encoded. Nikto does not have a timing option, however, and abnormal traffic patterns such as spikes can trigger alerts if the evasion techniques avoid signatures.

-------------------------------------------------

 Practical Scenario
The local network defenders of the City Hall network have recently incorporated a Demilitarized Zone (DMZ) and want to know of any scanning activities that might occur on the network segment. The CPT has been tasked with hunting any possible scanning activities on the segment. The local network defenders have a Systems and Information Event Manager (SIEM) configured, as well as network taps set up throughout the network. Locate any evidence of scanning activities.

﻿

DMZ Network: 172.35.3.0/24

﻿

1. Set your time range to the following: October 13, 2021 08:00 - October 13, 2021 09:30

﻿

2. Answer the following question based on the contents in Kibana.


![image](https://github.com/user-attachments/assets/8bb8e1b3-6ba4-49db-ad5b-673490c34da3)


![image](https://github.com/user-attachments/assets/5cc04021-a129-4011-9f92-4263a323c478)


![image](https://github.com/user-attachments/assets/caf9664d-26cf-4b61-9670-29c67034de49)























































































