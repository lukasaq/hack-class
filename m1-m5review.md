### ** m1,1 m2,1 m4,1 m5,1 ## m4,4 ## 
--------------------------------------------------------------
### *read intel brief of a threat actor* m1,1

most of what we need is in these areas in the pdf chech table of contents

Initial Infection Vectors 

Exploited Vulnerabilities 

Command and Control Infrastructure 

Malware 

use ctrl f with key words from the question

---------------------------------------------------------------------
#### *kibana query on ports ips source and destination and protocols* 





------------------------------------------------------------------------------
### *edit a sigma rule anf run it andd run it get query and take it to kibana* m2,1

my file with chnages
![image](https://github.com/user-attachments/assets/a89dd067-d405-4b38-a2ab-8bf522315434)

given file / original
![image](https://github.com/user-attachments/assets/609514e7-518e-4b8c-9722-83acf9333137)

command to get the query for kibana

python sigmac -t es-qs ../rules/windows/sysmon/sysmon_quarkspw_filedump.yml -c winlogbeat

![image](https://github.com/user-attachments/assets/8080784b-4fe1-4359-849e-c38e073383e0)



--------------------------------------------------------------------------
### *diffrence between the shells in linux borne again c shell posix* 

Comparing Linux Shells

Linux shells contain a wide range of features. The table below compares some of the most common shells and the systems in which they are found.

![image](https://github.com/user-attachments/assets/e4822f90-9146-46a7-8722-65ed61093351)



-------------------------------------------------------------------------
### *command line in linux to get network info ifconfig ip route ip addr netstat AND ALL SWITCHES* 





-------------------------------------------------------------------------
### *linux commands to view and inturpurt linux files and directore ls chmod* ##





-------------------------------------------------------------------------
### *analyze logs in linux* m4,4

Enter the following command to access root privileges on the host:
$ sudo su

When prompted, enter the password for the user trainee:
Password: CyberTraining1!

Enter the following command to access the log directory:
(root@kali-hunt)-[~] # cd /var/log/

Enter the following command to view the log directory:
(root@kali-hunt)-[/var/log] # ls

Step 6 returns the files within the directory, as displayed below in Figure 4.4-3:
![image](https://github.com/user-attachments/assets/ad3df09c-bec6-4208-af6e-6e64c5014e0e)
directory /var/log/ stores the log files on a Linux host.

Enter the following command to view the log directory:
(root@kali-hunt)-[/var/log] # less syslog

9. Enter the following command to view the log directory:
(root@kali-hunt)-[/var/log] # tail syslog



![image](https://github.com/user-attachments/assets/c91f4f89-fa5a-42d3-a735-3c6c54b5ec87)
![image](https://github.com/user-attachments/assets/9b1d4955-d2f1-4cbe-9dc1-a37675c09dd8)
![image](https://github.com/user-attachments/assets/73030cec-dc23-4efc-80cf-5e27600250b1)


apache log

Open Terminal Emulator.


3. Access the log file, located on the following path:
(trainee@kali-hunt)-[~] less /var/log/apache2/feb28_logs.log.1

![image](https://github.com/user-attachments/assets/cb9dbd48-d7b8-4cc5-9a7f-0cb6d905ddf6)


Attack Analysis

The logs contain information regarding a malicious attack to the vCityU web server. It was determined that the file r57.php is malicious and associated with the attack. The file likely included a large amount of bytes to upload to the server. Using this information, answer the next set of questions.

Bytes Uploaded

The following log entry contains 12459 bytes sent. The large number of bytes relative to the other logs, paired with its location, prior to any log containing r57.php, indicates this is likely the log of the malicious file upload.

﻿

71.55.82.68 - - [28/Feb/2022:09:05:41 +0100] "GET /vcity/student/plugin-install.php HTTP/1.1" 200 12459 "http://www.vcityu.com/victyu/student/plugin-install.php?tab=upload"

-------------------------------------------------------------------------
### *terminal commands to view a file cat less more nnano vi * ##






-------------------------------------------------------------------------
### *appache logs get host web request login php* m3,

written in 

apache log

Open Terminal Emulator.


3. Access the log file, located on the following path:
(trainee@kali-hunt)-[~] less /var/log/apache2/feb28_logs.log.1

![image](https://github.com/user-attachments/assets/cb9dbd48-d7b8-4cc5-9a7f-0cb6d905ddf6)

The following is an example of a log entry:
77.54.21.11 - - [12/Dec/2018:05:03:34 +0100] "GET /vcityu/student/documents.php?file=220.php&theme=twentysixteen HTTP/1.1" 200 4291 



This example includes the following elements:

Client IP address: 77.54.21.11

Time stamp: 12/Dec/2018:05:03:34 +0100

Type of request

Method: GET

Resource: /vcityu/student/documents.php?file=220.php&theme=twentysixteen

Protocol: HTTP/1.1

HTTP response code: 200

Bytes sent: 4291


![image](https://github.com/user-attachments/assets/08cfdf08-d3d8-4107-bec8-36326f9967a9)




-------------------------------------------------------------------------
### * process list to pull pid ps -elf parent pid aka ppid* m5,








-------------------------------------------------------------------------
### * use linux commands to identify services systemctl, status and services*
































-----------------------------------------
Q3
![image](https://github.com/user-attachments/assets/303c0ee5-cd57-4b22-8ba5-b88a64112028) 

Q4
![image](https://github.com/user-attachments/assets/fdf20519-4ee1-4907-be15-cea5048324b0)
Q5

![image](https://github.com/user-attachments/assets/703b2e61-5467-4e7e-90f9-72b68011ed3d)
![image](https://github.com/user-attachments/assets/cb465b60-5754-402a-bdf9-4b6dafb4405c)
Q7
diffrence in shells
Q8
mac address on linux
Q9

Q14
.103 not .102
![image](https://github.com/user-attachments/assets/a71d6779-7802-4ec3-acfe-3a1b0e21822c)

Q16
to get the parent process 
ps -elf | grep ncat
ps -elf

![image](https://github.com/user-attachments/assets/b2eb3902-181e-4d2a-9df0-a05d5d32f8a8)

Q17

![image](https://github.com/user-attachments/assets/3bd89688-e5e6-45b1-8b16-43c3c7d761df)
![image](https://github.com/user-attachments/assets/d4786886-97fb-495b-9940-d73bf24c8b6c)
or
![image](https://github.com/user-attachments/assets/d761170d-9ef4-4518-adc2-6a370b66ae1f)
![image](https://github.com/user-attachments/assets/d761170d-9ef4-4518-adc2-6a370b66ae1f)

ls
777 user group
rwxrwxrwx uiser group


![image](https://github.com/user-attachments/assets/de1b5f2d-47a3-4611-8ca1-1f766f274725)

![image](https://github.com/user-attachments/assets/101f9524-b52f-4ee6-9c36-ff5cbcd6187f)


![image](https://github.com/user-attachments/assets/78274fda-1595-479a-9250-2887155c0a23)

![image](https://github.com/user-attachments/assets/4549302f-32a6-462e-ad0c-af549b9fe60c)

![image](https://github.com/user-attachments/assets/22b5cd8b-4b6a-41a5-a343-0faf9f0b13be)




https://rcs08-portal.pcte.mil/#/events/outlook/structured-content/event-d719c4a3-c596-4b73-b4f6-ef837c3fcce9/exam/7e49c144-5e2e-4555-b338-75beaf8f0f6d



review 2 -----------------------------------------------------------------------------------

find net cat port 

ps -elf | nc
systemctl status | grep nc

-------------------------------------------

search for file names to see who got fished
ips to find ports

felds for workstation name
agent.name hostname

--------------

maybe add to script

| select -expandproperty message

--------------------

between 2 ips

104.53.222.103 and 172.16.5.2
payload name

host ip
source and destination ip

------------------

installed packages choose first one

dpkg -l 

-------------------

exe="program that is used"
cwd=" current working directory "

--------------------------
http method look for get or post

bytes from server response

read correct timestamp

-----------------------------

name of web shell

ls /var/www/html

linux persistence lesson

-----------------------
4,1 5,1 1,1 































