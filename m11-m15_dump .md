### CDAH-M14L3-Introduction to Volatility Framework ### 


Overview of the Volatility Framework
CDAs are generally focused on discovering how a system was compromised, and what was accessed or stolen from a system. Often, the only location where this information resides is in memory. Objects stored in memory such as running processes are unrecoverable after a system is shut down unless they are captured in a memory dump or hibernation file. Even if a memory dump is available for analysis, many questions come to mind, such as how to analyze it, what it contains, and what tool(s) are needed. The answer to those questions lies within the Volatility framework. 

﻿

Volatility is the most widely used framework for extracting digital artifacts from volatile memory, also known as RAM. There are two commonly-used versions of Volatility: version 2 was released in 2007 and maintained until 2016, and version 3 was released in 2019 and is the current version that is continuously updated by the Volatility Foundation. Volatility 3 is still in development and is missing some of the functionality of version 2, which is why the main focus of this training is using Volatility 2. Volatility supports Windows, Mac, Linux, and Android Operating Systems (OS). Both Linux and Android require a custom profile to be created for the memory image to be read by Volatility.

﻿

Windows users have two options for using Volatility. The standard version uses Python, and the executable version of Volatility comes pre-wrapped with the default plugins and profiles. 

﻿

Volatility Symbols/Profiles
﻿

Symbols and profiles are the defining structures unique to each version of the OS and the architecture of where information in the memory is stored. Volatility has preconfigured the most common OS platforms and versions in symbols/profiles. Volatility 3 refers to these structures as symbols and Volatility 2 as profiles.

﻿

For example, a 32-bit version of Windows 10 has a different memory address space than a 64-bit version of Windows 10. If the incorrect profile is selected, Volatility may not be able to extract information from the memory image. It can be quite frustrating trying to determine which profile the memory image belongs to. The developers of Volatility 3 took that into account during its development and created the ability for Volatility 3 to automatically detect which profile/symbol pack is needed to analyze the image. If the symbol pack is not in the current installation of Volatility 3, the Volatility application automatically downloads the correct profile when the image is being analyzed but does not automatically download symbols for the Linux images. The most common Linux distributions and Mac versions have profiles available for download from Volatility’s website.

﻿

Volatility 2, on the other hand, requires the analyst to determine which profile to employ by using the imageinfo plugin to read the image. Sometimes the profile does not exist even under Volatility 3, and the profile needs to be manually created. Most versions of Linux need a custom profile created.

﻿

Creating a Custom Profile
﻿

Due to the multiple Linux distributions, Volatility does not have a default profile to support all Linux versions. The process of creating a custom profile is challenging at first but highly recommended to understand.

Install the exact kernel version of Linux in a Virtual Machine (VM) that matches the memory image.
Download the latest version of Volatility inside the VM.
Install dwarfdump if not already installed.
Navigate to the volatility/tools/linux/ directory.
Execute the make command.
Back out of the volatility directory to the parent directory (cd ../../../).
Run the following command to create the profile: 
zip $(lsb_release -i -s)_$(uname -r)_profile.zip ./volatility/tools/linux/module.dwarf /boot/System.map-$(uname -r)

This generates a profile by creating a zip file that includes the module.dwarf file and the  System.map  file for the specific Linux distribution and kernel version. This profile can then be used by Volatility to analyze memory dumps from Linux systems.

Copy the VERSION_profile.zip file to the volatility/volatility/plugins/overlays/linux directory.
Run vol.py –info to verify the profile is in Table 14.3-1:

![image](https://github.com/user-attachments/assets/75399b9b-d768-409c-bf65-f1d9e6401f00)

Plugins


The power of Volatility is in the plugins. The plugins listed in Table 14.3-2 search through the memory image to find information of value and provide context of where that information originated.


![image](https://github.com/user-attachments/assets/aedecb5e-bc33-4570-a222-d140a30c19da)




Many plugins do not ship with Volatility by default. Most were created from competitions hosted by the Volatility Foundation that take place each year. One plugin that is not standard in Volatility 2 is called bitlocker and extracts the Windows BitLocker key out of memory so that it can be used to decrypt the hard disk. These additional plugins are downloaded from Volatility’s Github repository and placed within the appropriate folder to work on a local installation of Volatility.


Differences between Volatility 2 and 3

![image](https://github.com/user-attachments/assets/c1e4df69-00d3-49d6-a2cd-6284e0a697ea)




Volatility 2 and 3 each have minimal syntax differences. Volatility 2 does not require a label in front of the plugin name for Windows memory images. Volatility 3 plugins are prepended with the windows. label. The following command displays all the local user accounts and their password hashes from memory:
Volatility 2: python2.7 vol.py -f memoryfile.raw hashdumpVolatility 3: python3 vol.py -f memoryfile.raw windows.hashdump
Volatility 3 does not require providing a profile as Volatility 2 does:
Volatility 2: python2.7 -f memoryfile.raw –profile=Win10x64_19041 pslistVolatility 3: python3 -f memoryfile.raw windows.pslist
NOTE: For Volatility 2, the imageinfo plugin should be run to attempt to detect the correct profile. 


To see all of the available plugins, run the following command:
Volatility 2: python2.7 vol.py –infoVolatility 3: python3 vol.py -h

![image](https://github.com/user-attachments/assets/86e91979-f435-41f2-b411-f365e259fd84)

![image](https://github.com/user-attachments/assets/576d8495-ba01-494a-a6e4-18d3001978f8)

![image](https://github.com/user-attachments/assets/6e58f339-6ee5-4b6f-b5ca-bce7fb31e0f3)

-------------


Finding Artifacts in a Memory Dump
When analyzing a memory image with Volatility, first determine the profile that is compatible with the image. The imageinfo plugin allows Volatility to examine the imageusing additional plugins.  

﻿

Detecting the Profile
﻿

Running the following command tells Volatility to detect the required profile:

python2.7 vol.py -f memory image.raw imageinfo
﻿

Volatility returns multiple profile options. It is best to know which OS the image uses to select the correct profile. 

﻿![image](https://github.com/user-attachments/assets/e3d48a2d-26ca-4328-991d-ae1f9e38a709)


Also, by running python2.7 vol.py -f memoryimage.raw –info, the list of profiles available is displayed.


If Volatility cannot determine the profile, select one from the list of profiles if it is known which profile to use. It is possible that there is an error with the image or additional steps may need to be taken to use that image. For example, if a Windows 10 hibernation file is taken directly from a Windows 10 host and read with Volatility, it fails because the file is compressed. A third-party tool (Hibr2Bin) needs to be run before Volatility can examine the image. It may be necessary to run the strings utility against the image manually, looking for Windows and a version number to find the correct version.


Extracting Artifacts


After the profile is found, the profile and a plugin that correlates to the information to be gleaned from the image must be specified. Some plugins have multiple parameters required. The -h parameter is used to see which ones are required. For example, the dumpfiles plugin requires a process ID, Regular Expression (regex), or a memory address along with an output directory to save the file:
python2.7 vol.py -f memoryimage.raw –profile=Win10x86_10941 dumpfiles -h

Process List


There are three plugins that provide information about which processes were running at the time of the memory capture: pslist, pstree, and psxview.

![image](https://github.com/user-attachments/assets/78476807-e7c2-49a0-a1e6-f91091cd11ac)


Typically, pslist or pstree are all that is needed, but psxview is particularly useful when there are processes that are hidden due to a rootkit or similar type of malware:
python2.7 vol.py -f memoryimage.raw –profile=Win10x86_10941 pslist
python2.7 vol.py -f memoryimage.raw –profile=Win10x86_10941 pstree
python2.7 vol.py -f memoryimage.raw –profile=Win10x86_10941 psxview



Process Command Line


This plugin displays the full file path of a running process and which parameters were provided at the time it ran. For example, a malicious file running from an unusual directory has the filename of a legitimate application. The Process Command Line (cmdline) plugin displays the command lines to help identify the malicious process. This also works well when the process running is a word processing software application, and the goal is to determine which file was open at the time of the capture.
python2.7 vol.py -f memoryimage.raw –profile=Win10x86_10941 cmdline



Process Dump


The Process Dump (procdump) plugin extracts the binary that was running in memory and saves it to disk. This is useful for malware analysis, creating Indicators of Compromise (IOC), and so on.
python2.7 vol.py -f memoryimage.raw –profile=Win10x86_10941 procdump -p processidnumber -D destinationtosavethefile



Memory Dump


The Memory Dump (memdump) plugin works best when an application such as notepad.exe is open, and there is some text in it, but the file has not been saved or written to disk. The memdump plugin extracts any data in the memory of the notepad.exe process.
python2.7 vol.py -f memoryimage.raw –profile=Win10x86_10941 memdump -p processidnumber –dump-dir destinationtosavethefile



Master File Table


The Master File Table (MFT) on Windows stores a record of all files modified, created, or deleted since the installation of the OS. The MFT Parser (mftparser) provides that information to a defender to view files, dates/times, and the file attributes associated with those files. This is used to build a clear picture of activity in a given time range and to potentially identify files of interest that may be worth investigating further.
python2.7 vol.py -f memoryimage.raw –profile=Win10x86_10941 mftparser



File Scanner


The File Scanner (filescan) plugin searches through the memory image, looking for files that are available within the image and obtains their physical address in memory. This address is used to extract the file out of memory and write it to the trainee’s workstation.
python2.7 vol.py -f memoryimage.raw –profile=Win10x86_10941 filescan



Dumping Files


The ability to extract files out of a memory image is incredibly useful when investigating a malware case such as opening a malicious Microsoft Word document. The Dumping Files (dumpfiles) plugin, when used in conjunction with the filescan plugin, allows the file to be extracted from memory to be analyzed later for further IOCs.


The two main options are to use a regex to find a file within a specific process or to extract a file by its physical memory address.
Regex

python2.7 vol.py -f memoryimage.raw –profile=Win10x86_10941 dumpfiles -p processidnumber -r REGEXOFFILENAME -n -D destinationtosavethefile

Physical Address

python2.7 vol.py -f memoryimage.raw –profile=Win10x86_10941 dumpfiles -Q MEMORYADDRESS -n -D destinationtosavethefile



The -n option keeps the filename the same as it is in memory. Otherwise, Volatility names the file as the memory address, which may be difficult to recall what file was extracted.


Network Connections


The plugins for discovering the network state of the host during the image capture are limited to three plugins: netscan, connections, and sockets. Each plugin is only valid on selected Windows versions, as shown in Table 14.3-5. 


![image](https://github.com/user-attachments/assets/c3b8a5cc-3702-4298-9749-f9d697f867ac)

The output of these commands is similar to the Windows netstat command, which shows the Internet Protocol (IP) address of the client, remote host, source and destination ports, process name, process ID, and date the connection started. 
python2.7 vol.py -f memoryimage.raw –profile=WinXPSP2x86 connections
python2.7 vol.py -f memoryimage.raw –profile=Win10x86_10941 netscan
python2.7 vol.py -f memoryimage.raw –profile=WinXPSP2x86 sockets



The only difference between these plugins is that connections and netscan plugins only produce Transmission Control Protocol (TCP) connections whereas sockets produces connections including TCP, User Datagram Protocol (UDP), and raw connections.


Credential Dumping


This plugin may seem like it is only for offensive purposes, but CDAs use it, too. The hashdump plugin extracts the username and password hashes of all local accounts on the system at the time of the memory capture. This information is useful to determine whether a new account was added to the system, or if the administrator account had a blank or weak password.
python2.7 vol.py -f memoryimage.raw –profile=Win10x86_10941 hashdump



Unique Strings


The Unique Strings (strings) plugin is useful for searching through a memory image for specific strings to see if they exist. It could be an IP address, part of a word, or filename. Sometimes finding a remnant of known activity is all that is needed to prove there was potentially Malicious Cyberspace Activity (MCA) on the system at one point. Unfortunately, the strings plugin does not show where the content comes from within the image to provide context, strictly showing if there is a match.
python2.7 vol.py -f memoryimage.raw –profile=Win10x86_10941 
string
s -s listofartifacts.txt

![image](https://github.com/user-attachments/assets/a602d57c-8e0a-447f-9a58-241547abacaf)
![image](https://github.com/user-attachments/assets/f2f7c046-3741-440e-81d0-38668fc73e37)


----------------------


Intelligence Tipper
Using Volatility, locate a specific artifact provided by threat intelligence. The artifact may not be saved in files and may include text typed into a notepad.exe process that is only in memory. The goal is to use a mixture of Volatility plugins and a regex to find the indicator.

﻿
Workflow 
﻿

1. Log in to the VM ubuntu20 using the following credentials: 

Username: trainee
Password: CyberTraining1!
﻿

2. Open a terminal and execute the following to change into the volatility-master directory:

cd volatility-master


![image](https://github.com/user-attachments/assets/ec90c33c-c489-4af4-92cd-08cca7f61e23)


3. Execute the following to obtain a list of running processes:
python vol.py -f ~/Desktop/Triage-Memory.mem --profile=Win7SP1x64 pslist



4. Execute the following to obtain the process ID of the notepad.exe process:
python vol.py -f ~/Desktop/Triage-Memory.mem --profile=Win7SP1x64 pslist|grep notepad


![image](https://github.com/user-attachments/assets/b47a517b-445c-4c79-a859-b31b5f08f4cd)

5. Execute the following to dump the memory of the notepad process to disk:
python vol.py -f ~/Desktop/Triage-Memory.mem --profile=Win7SP1x64 memdump -p 3032 --dump-dir /home/trainee/

![image](https://github.com/user-attachments/assets/f119315a-4415-4a96-9099-7214bf81b3f9)

6. Execute the following to search through the newly created dump file via strings and regex:
strings -el ../3032.dmp |egrep 'flag<R'

![image](https://github.com/user-attachments/assets/b91245d7-3e7f-4b54-a077-630a0fad68e1)

![image](https://github.com/user-attachments/assets/e6830239-e7c8-4bb7-b0fb-70df7b71dc8b)

---------------

Test Case with Python
Python scripts are used to assist with analyzing memory dumps with Volatility. It can become time-consuming searching for plugins, waiting for Volatility to complete, and reviewing the output. Frequently a defender runs a plugin to view its output, reviews it, runs another plugin, and overwrites the output in the terminal. Often that previous output is needed to make sense of the current data being observed, and the cycle repeats itself and causes analysis to take longer.

﻿

A best practice solution is to output the most commonly used plugins to their own files so that they are reviewed repeatedly without needing to rerun Volatility to extract the information a second or third time. Another benefit to writing the output of each plugin to a file is that it allows for quick searching across all plugin output to see where there are connections. Using this method, a list of IOCs is placed within a file and used to search through the output of the Volatility plugins to see if there is a match. This is particularly useful if a memory image is collected from a system where it is possible that it is compromised by a known malware variant but still requires analysis to verify. By using a list of already known artifacts/IOCs, the image is quickly parsed, and the defender can answer whether it was infected by the same strain of malware or not. The IOC list includes information such as an IP address, process name, filename, timestamp, or a unique identifier that may be in the output of one of the plugins.

-----------------

Using Python to Automate the Extraction of Artifacts with Volatility
Create a Python script that automates the extraction of content from a memory image using a list of common plugins. Use a list of IOCs from another file to find if and where they are present in a memory image. 

﻿

Workflow
﻿

1. Log in to the VM ubuntu20 using the following credentials: 

Username: trainee
Password: CyberTraining1!
﻿

2. Edit the voldump.py script located in the /home/trainee/Desktop/results folder and add the plugins listed on line 4 to automate their execution:

plugins = ['psxview', 'pstree', 'netscan', ' malfind', 'mftparser', 'filescan', 'dlllist', 'cmdscan', 'cmdline', ' shimcache', 'shellbags']


![image](https://github.com/user-attachments/assets/826f1fd7-63de-4e49-a0f2-b6357becfdd5)

3. Open a terminal and change to the directory where voldump.py was saved:
cd /home/trainee/Desktop/results



4. Run the following command to execute the list of plugins mentioned in Step 2:
python voldump.py ~/Desktop/Triage-Memory.mem Win7SP1x64

![image](https://github.com/user-attachments/assets/2d5cfd40-353b-4e53-a0a1-a209f1d9fe6f)

NOTE: It takes three to four minutes for the script to complete but provides a status as it is running.

![image](https://github.com/user-attachments/assets/3016afc4-22d4-4991-9c14-871971b894a0)

5. Once the script is complete, verify the current directory contents to ensure the text files were created:
ls *.txt



6. Review the predefined list of IOCs used for searching within the image to become familiar with them:
cat ~/Documents/IOCs.txt


![image](https://github.com/user-attachments/assets/33c4e238-5b01-4f88-a51f-e21b861973c2)

7. Run the following command to use the previously mentioned list of IOCs to search the output generated by voldump.py:
cat ~/Documents/IOCs.txt | xargs -i egrep -i {} *.txt

![image](https://github.com/user-attachments/assets/3b70415d-c1f2-4d4f-ba77-f64eee765d9a)


8. Review the output to see IOCs/artifacts are present in the image and from which plugins/files:

![image](https://github.com/user-attachments/assets/7abebf51-826c-4b27-a561-66b35295c2f1)

![image](https://github.com/user-attachments/assets/193be993-323d-44af-a26f-26b0d995f07a)
![image](https://github.com/user-attachments/assets/8f6cf02d-fbf1-4880-b8e1-ac8a9c888e4b)
![image](https://github.com/user-attachments/assets/bfa1d708-308d-4b0c-b544-4cf3d061e70b)
![image](https://github.com/user-attachments/assets/bbe4c2e4-d8d1-4074-bf22-42fb5ba5e5f8)














