### CDAH-M28L1-Analyzing a Compromised Host ###

Host Incident Response and Forensics
When an incident is suspected on a host, analysis and forensics must begin immediately. As covered in prior Cyber Defense Analyst – Host (CDA-H) lessons, the IR process begins by identifying whether an incident has occurred and the initial impacts to operations. The process of identifying the initial compromise of a host requires an understanding of certain tools as well as providing IOCs for analysis. IOCs found in diagnosing an incident occurrence are crucial to all stages of the IR process. Additionally, the tools used to identify IOCs, such as Autopsy and Volatility, are often used for later stages of the IR process, including evidence gathering.

------------------

Review of Host Forensics Tools
The following are common tools used for host forensics.

﻿

Forensic Toolkit
﻿

Forensic Toolkit® (FTK®) is a full suite of tools to conduct forensic analysis. The following are common capabilities of FTK:

Process forensic images
Decryption and password cracking
Parsing of registry files
Visualizations

FTK® Imager is available as a stand-alone, free tool and can be used to create forensic images. Forensic images can be used for analysis and serve as a great tool for identifying nefarious activity or suspected malware on a compromised host.

﻿

Autopsy
﻿

Autopsy is used to forensically analyze disks or disk images to identify artifacts of malicious activity. Autopsy can be used to analyze malware behavior as well as extract artifacts and full malware. In conjunction with FTK Imager, Autopsy provides an open-source solution for conducting full-disk forensic analysis.

﻿

Volatility
﻿

Volatility is used to capture images of memory in a compromised host. This preserves the state of memory that a system is in when an attack occurs. Volatility can also be used to analyze and extract artifacts of malware activity. Volatility has custom plug-ins that can be used to provide new capabilities, such as VolDiff, which adds a memory malware footprint analysis. 

﻿

Cuckoo Sandbox
﻿

Cuckoo Sandbox is a sandbox tool equipped with automated malware analysis. Cuckoo executes malware in a sandbox environment and then provides an automated report of the malware behavior. This report can be used to identify artifacts and additional compromises caused by the malware.


-----------


Extracting Indicators of Compromise with Forensics Tools
Extracting IOCs with Volatility
﻿

Understanding the state of a compromised machine depends on gathering a snapshot of the memory of a compromised host. This can be done with Volatility and its memory-imaging capability. Volatility creates a .vmem file, which is a snapshot of the host’s memory and provides access to all processes and functions running at the time of creation. If malware or malicious processes are running, they can be identified through analysis of this image.

﻿

Conducting analysis with Volatility is possible by directly analyzing the memory image or by using plug-ins to automate some analysis for specific behaviors. Volatility plug-ins can be used to detect specific activities, such as malware in Hypertext Transfer Protocol (HTTP) packets found in memory images. Malicious processes or artifacts found in memory can be extracted using Volatility.

﻿

Memory Malware Extraction Process
﻿

Identification of profiles is a necessity to ensure that Volatility can scan properly. The profile is based on the type of image being used. Identifying the needed profile is done with the kdbgscan command:

$ python vol.py -f (Insert Image Name) kdbgscan
﻿

Once a profile has been identified, Volatility can be used to scan and analyze the memory image. The command pslist can be used to display the processes running on the system at the time of the image capture:

python vol.py -f ~(Insert Image Name) --profile=(Insert profile found in kdbgscan) pslist
﻿

If a malicious process is suspected and an analyst wants to conduct further analysis, the process can be extracted using the procdump command. This command extracts the executable, and other tools, such as Cuckoo Sandbox, can be used to further analyze the executable for malware.

python vol.py -f (Insert Image Name) --profile=(Insert profile found in kdbgscan) procdump -D dump/ -p (Insert Process Name)
﻿

Many other commands are available through Volatility to meet specific situations and needs. Analyzing the memory of an image can be a giveaway to malicious activity that occurred on a host. Analysts must understand how to use Volatility to adequately defend and eradicate during ongoing incidents. 

﻿

Extracting IOCs with FTK/Autopsy
﻿

Creating forensic disk images is key to understanding the state of a compromised system, enabling analysis of the malware artifacts. FTK Imager can create these forensic images, and FTK or Autopsy can provide analysis capabilities for forensic disk images.

﻿

Autopsy has automated and manual tools that allow for the inspection of forensic images and help to find artifacts of malicious activity. Malware and artifacts can be extracted from these images for further analysis. 

﻿

For this lesson, Autopsy is used to analyze and extract IOCs.

﻿

Disk Malware Extraction Process
﻿

Using Autopsy is simpler than using other command-line tools due to its intuitive User Interface (UI). The UI allows the user to select forensic images to ingest and inspect. The process for inspecting images with Autopsy is as follows:

﻿

1. Create a Case: A case is a container for data sources that must be created before data is analyzed.

2. Add a Data Source: Data sources are added to the case. Data sources include disk images or local files.

3. Analyze with Ingest Modules: Ingest modules operate in the background to analyze the data. Results are posted to the interface in real time and provide alerts as necessary. 

4. Perform Manual Analysis: The user navigates the interface, file contents, and ingest module results to identify the evidence.

5. Generate a Report: The user initiates a final report based on selected tags or results.

﻿

Figure 28.1-1 illustrates this process:

<img width="1667" height="834" alt="image" src="https://github.com/user-attachments/assets/7f29e95b-b6c5-4d83-98c9-3f519c9b8247" />


Autopsy can provide numerous artifacts for analysts to identify compromise of a host. Autopsy also helps provide details to ensure that threats can be eradicated further in the IR process


-------------


Malware Analysis
After malware has been extracted, additional steps can be taken to analyze the full extent of the malware’s capabilities and follow-on actions that the malware may have conducted. A sandbox environment is needed for this analysis.

﻿

Cuckoo Sandbox provides the capability to execute malware in a safe environment while also providing automated malware analysis. Cuckoo creates a malware behavior report that provides details on the malware capabilities and the extent of the malware’s infection in the sandbox. The attached Portable Document Format (PDF) file provides an example of a Cuckoo malware report.





-----------------


Perform Host Forensic Analysis
A user reports that their system has been acting strangely and the company’s firewall has been reporting strange traffic originating from the system. The machine has been forensically imaged. The following lab demonstrates performance of host malware analysis:

Locate the malware on the system.

Extract the simulated malware using Volatility/Autopsy.

Extract malicious behavior from the malware using Cuckoo Sandbox.

Analyze memory for additional IOCs using Volatility, and extract IOCs from the disk image using Autopsy.


Identify the Malware for Analysis
﻿

Complete the steps in the following workflow to identify the malware to be analyzed, using Volatility.

﻿

Workflow
﻿

1. Open the Virtual Machine (VM) cuckoo. The login credentials are as follows:

Username: trainee
Password: CyberTraining1!
﻿


2. Open the desktop folder Lab1, right-click and select Open in Terminal.

﻿


3. Run the following command to determine the type of profile needed to examine the memory capture:

volatility imageinfo -f Lab1.vmem
NOTE: Check all commands for errors after pasting them into a terminal.﻿

﻿

The output clarifies that the best profile for this memory capture is WinXPSP2x64.

﻿


4. Run the following command to analyze processes in the memory image:

volatility pstree -f Lab1.vmem --profile=WinXPSP2x64
﻿

The output shows that an executable that should not be there is running in memory. The executable, toteslegit.exe, is not a normal Windows executable and should be examined further.

﻿


5. Run the following command to view the open connections on the system when the memory was captured:

volatility connscan -f Lab1.vmem --profile=WinXPSP2x64
﻿

Two listed connections are returned. Two identical Process Identifiers (PID) are returned for the same process. This is because one is in physical memory, or Random Access Memory (RAM), and the other is mirrored in the system pagefile. They both point to the same PID, which is listed in the command from Step 4. The PID is attached to the executable toteslegit.exe, whose associated PID is 2660.

﻿

Extract the Malware, and Make It Available for Analysis 
﻿

Complete the steps in the following workflow to extract the executable from the disk image and make it available for malware analysis.

﻿

Workflow
﻿

1. Open a web browser, and input the Uniform Resource Locator (URL) localhost:9999/autopsy to access the running Autopsy web service.

﻿

2. Select New Case.

﻿


3. In the Case Name field, enter toteslegit, and select New Case at the bottom of the page.

﻿


4. Select Add Host on the next screen.

﻿


5. Select Add Host.

﻿


6. Select Add Image.

﻿


7. Select Add Image File.

﻿


8. In the Location box, enter /home/trainee/Desktop/Lab1/Lab1.E01. Leave the Type selection as Disk and the Import Method as Symlink.

﻿


9. Select Next at the bottom of the page.

﻿


10. Select Add.

﻿


11. Select OK.

﻿

The next screen lists the file image options.

﻿


12. Select the radio button next to C:/, and select Analyze under it.

﻿


13. Select File Analysis at the top of the screen.

﻿


14. Enter toteslegit in the File Name search box.

﻿

The first file returned is the malicious executable file.

﻿


15. Select the name of the malicious executable to view the contents of the file.

﻿

Because the file is a compiled binary, it is not possible to see all of its contents. 

﻿


16. To save the file to disk so that it may be examined in a malware sandbox, select Export, and select Save File when the dialog box appears.

﻿

Analyze the Malware
﻿

Complete the steps in the following workflow to analyze the malware using Cuckoo Sandbox.

﻿

Workflow
﻿

1. Open a web browser, and enter localhost:8080 in the address bar.

﻿


2. In the Cuckoo Sandbox interface that appears, select Submit a file for analysis.

﻿


3. In the dialog box, select Downloads to access the directory that the malicious executable is saved in.

﻿


4. Select the malicious file, vol2-C.Documents.and.Settings.Administrator.My.Documents.toteslegit.exe, to load it into Cuckoo for analysis.

﻿


5. Select Analyze in the upper right corner of the window that opens.

﻿


When the analysis is complete, the status indicator on the right side changes from Running to Reported.

﻿

6. Select the name of the file to open a new tab displaying the results of the scan.

﻿


7. Scroll down the summary window, and view the findings. 

﻿

Stealthy malware sometimes returns few findings in a malware sandbox due to features that prevent detection. Malware authors commonly use a custom packer that can obfuscate the contents of the malware from scanners. The malware in this workflow has been packed in this way.

﻿

8. Review the Signature findings and Behavioral Analysis tabs in Cuckoo to review details of the malware as shown below:



<img width="1358" height="445" alt="image" src="https://github.com/user-attachments/assets/b34a9d9d-c1d4-4f24-87ee-b0a74becd6bf" />

<img width="1244" height="591" alt="image" src="https://github.com/user-attachments/assets/e79f25f5-26a0-45f1-9a66-10bd9ac49921" />

The behavioral analysis tab is visible through the menu on the left side of Cuckoo’s display. 


Use this workflow to answer the following questions.


Keep the VM open, as it is used in an upcoming workflow


-------------


Attack Entry Points
When an incident is suspected, it is important to identify the primary entry point of the malware. The primary entry point is generally found when gathering evidence in the incident. Identifying this initial entry is key to understanding the depth of the attack and helps to improve defenses when remediated.

﻿

However, when malware compromises a host, additional entry points are often created. These attack vectors are referred to as secondary and tertiary entry points. A secondary entry point is an alternative entry point that an attacker provides for themselves to ensure accessibility to a system or network. Tertiary entry points can be any number of additional entry points created by the attacker to further ensure accessibility to a system or network. Both secondary and tertiary entry points incorporate the same techniques. All additional entry points, including both tertiary and secondary, provide new methods of entry so that defenders have more difficulty stopping the attack. Identifying additional entry points is critical to completely remediating a compromised host.

﻿

Identifying attackers’ additional entry points requires an understanding of common secondary and tertiary threat actor entry points. Common techniques for creating additional entry points include the following (and are shown in Figure 38.1-2):

Finding additional exposed or insecure assets.
Removing security controls.
Sending phishing emails.
Generating backdoors.
Creating new accounts.
Performing drive-by downloads.
﻿
<img width="1667" height="834" alt="image" src="https://github.com/user-attachments/assets/930ad4b9-92d1-4a36-9a41-a2fc5a46baa1" />


When reviewing an incident, analysts must trace all activity conducted by the attacker to identify secondary or tertiary entry points and prevent future follow-on compromises of the attack. Entry points can be detected through such methods as analysis with Volatility or Autopsy, and Cuckoo Sandbox can also identify some entry methods associated with malware.


-------------

Identify Additional Attack Entry Points
An attacker recently targeted an organization with a phishing campaign. The phishing emails had a malicious executable attached and were used to establish a foothold in the organization’s systems. In the following lab, discover an additional entry point and analyze the activity that resulted from its use.

﻿

Find a Phishing Email Attack Entry Point
﻿

Complete the steps in the following workflow to find a phishing email in memory and extract the URL of a malicious link in the email, using Volatility.

﻿

The VM should still be open from the prior workflow. If it is not open, log in using the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

Workflow
﻿


1. Open the desktop folder Lab2, right-click and select Open in Terminal.

﻿


2. Run the following command to determine the type of profile needed to examine the memory capture:

volatility imageinfo -f Lab2.vmem
﻿

The output shows that the best profile for this memory capture is WinXPSP2x64. 

﻿


The user reports that the email was in their inbox and that they saved the email to their My Documents folder with the filename important!. 

﻿

3. Run the following command to locate the file in memory:

volatility -f Lab2.vmem --profile=WinXPSP2x64 filescan | grep important
﻿


The returned output shows a single email and a link file. The first returned result is the saved email in the user’s My Documents folder. 

﻿

4. To extract the email from the memory capture, run the following command:

sudo volatility -f Lab2.vmem -–profile=WinXPSP2x64 dumpfiles –Q 0x0000000002ea3720 –n –D /home/trainee/Desktop/Lab2
﻿

This command extracts the email message and saves it to the Lab 2 folder with the filename file.None.0xfffffadfe74e7cf0.important!.eml.dat.

﻿


5. To view the contents of the email, run the following command:

strings 'file.None.0xfffffadfe74e7cf0.important!.eml.dat'
﻿

Using this workflow, answer the following question.

﻿

Keep the VM open, as it is used in the next workflow.


---------------------


Find a Drive-By Download Attack Entry Point
Complete the steps in the following workflow to find the URL in memory of a drive-by download and extract the URL of the malicious link, using Volatility. 

﻿

The VM should still be open from the prior workflow. If it is not open, log in using the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

Workflow
﻿


1. Open the desktop folder Lab3, right-click and select Open in Terminal.

﻿


2. Run the following command to determine the type of profile needed to examine the memory capture: 

volatility imageinfo -f Lab3.vmem
﻿

The output shows that the best profile for this scan is WinXPSP2x64.

﻿


3. Run the following command to check the process list to see which web browser the user was running:

volatility –f Lab3.vmem --profile=WinXPSP2x64 pslist
﻿

﻿IEXPLORE.EXE is running on the system, with PID 648.

﻿

4. Execute the following command to pull the browser history from memory and identify the malicious link:

volatility –f Lab3.vmem –-profile=WinXPSP2x64 iehistory
﻿

Use this workflow to answer the following question.


-----------------


### CDAH-M28L2-Breach Scoping and Evidence Gathering ###


Gathering Threat Intelligence
Understanding the depth of an attack allows Host Analysts to defend against malicious threat actors. The investigation begins as soon as an initial breach is discovered. 

﻿

Having a clear methodology for gathering threat intelligence allows Host Analysts to use their time and resources efficiently. After an incident has occurred and been properly identified, threat intelligence must be gathered, as seen in Figure 28.2-1 below.

﻿

The four steps, or phases, of the process of gathering threat intelligence are as follows:

Scope
Analyze
Extract
Report

<img width="2048" height="675" alt="image" src="https://github.com/user-attachments/assets/685e55ec-4ef7-4d47-b9ce-6fbd16924bf0" />



Each phase of the intelligence-gathering and reporting process relies on one another. If the scope of an investigation is not fully known, but the team moves to the analysis stage anyway, there may be critical assets breached by an attack that go unnoticed due to improper categorization of the scope of the event. 


The same principle applies to each phase of this process. Each phase must be thoroughly conducted in order to adequately perform investigations and incident response.



---------------

Scoping, Analyzing, and Extracting Evidence
Identify the Scope
﻿

If a breach occurs, defensive operators must gather a thorough understanding of all affected assets and software. 

﻿

This process is known as Breach Scoping, as seen in part one of Figure 28.2-2 below:


<img width="2048" height="1024" alt="image" src="https://github.com/user-attachments/assets/c4b891a1-f336-4b61-aaf5-f4ef55e277cc" />

Breach Scoping helps cyber defense analysts understand the entirety of a threat, and provides assets for the investigation. After an attack has occurred, analysts must survey the organization’s network for indicators of assets that may be potentially involved in the scope of the attack. 


Common tools for identifying potential attacker activity are Security Incident and Event Management (SIEM) systems, and Intrusion Detection Systems (IDS). These tools help generate alerts and allow analysts to search and view devices that have evidence of threat actor activity. 


When identifying the scope of the breach, specific searches are conducted to determine all involved assets. Searches help create a list that can be used to categorize all possible devices that may have been accessed by threat actor activity. Once all assets involved in the scope of the attack are identified, defenders can start gathering threat intelligence.


Gather Evidence


When a breach occurs, an investigation must be opened. After initial access and the scope of the breach has been identified, finding key details of threat actor activity is the next step. This process is referred to as Acquiring Cyber Threat Intelligence (CTI).


Analyze and Extract Evidence


As with the breach scope, a SIEM can be used to identify threat actor activity and potentially malicious software. Additionally, an IDS may discover malware in transit across the network. 


Identifying malicious activity leads to analyzing any malicious files and software. Threat actors often execute malicious files after breaching networks. In order to understand the malware, any afflicted assets must be quarantined and forensic images should be created of their memory and disks. 


The quarantining process is dictated by the organization’s Incident Response Team (IRT). The IRT is responsible for executing the quarantine process (if possible) for any afflicted devices. When a device is quarantined, the forensic images can be used to transport the state of the system, as well as to retain any malware or malicious activities. Once images are created, specialized tools can be used to analyze the images and find threat actor activity. 


Extracting Evidence with Volatility and Autopsy
Volatility can be used to analyze and gather evidence of additional threat actor activity. In the memory images of an attacked device, artifacts are left behind. These artifacts can be used to identify specific actions that occurred, or files that were executed.


If a malicious file is executed, the file can be analyzed and extracted. Autopsy works similarly to Volatility, but with system disk images. Any malicious files or traceable actions left on system disks can be analyzed and extracted using Autopsy.


Executing Malware with Cuckoo
When malware is extracted by Volatility or Autopsy, the malware can be executed in a safe environment, such as Cuckoo. Cuckoo helps identify the characteristics of a malicious file, such as activities caused by malware. Cuckoo generates a report of the malware that provides details such as a rating of the malware’s malicious capability, actions capable by the malware, and more. 


Once evidence has been gathered, a full report can be created of the incident.


-------------------



Identify the Scope
An attacker used malware to compromise multiple hosts on an organization’s network. Initial malware delivery results in the compromise of one host and the attacker pivots with additional malware to compromise additional hosts. 

﻿

Use Elastic to identify the scope of the breach and determine indicators of additional compromised hosts.

﻿

Workflow
﻿

1. Log in to the Virtual Machine (VM) cuckoo-hunt with the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Open Firefox and go to the Elastic instance by entering the following address:

https://199.63.64.92/
﻿

3. Log in to Security Onion with the following credentials:

Username: trainee@jdmss.lan
Password: CyberTraining1!
﻿

4. Select Kibana from the left pane. 

﻿

5. Set the Time Range filter to Feb 7 2023 between 13:30 and 13:50.

﻿

Scope the breach of the attack by finding any devices connected to the attacker’s Internet Protocol (IP) address. The details from the initial attack were reported as coming from user Tammy Wall. 

﻿

6. Enter the following filter to see logs from this user:

user.name: tammy.wall
﻿

The host IP of the device used by tammy.wall is 172.16.4.4. The device usage details can be inferred since the source.ip field is part of the internal subnet and presents login and connection data for this user. This activity is not considered irregular. 

﻿

7. On the Available Fields menu, select the Destination IP field to see a list of the top IPs with which this device opened connections.

﻿

Any IPs within the 172.16 subnets are part of the organization. As seen in Figure 28.2-3 below, the IP 104.53.222.103 is likely not part of the organization. 

<img width="494" height="731" alt="image" src="https://github.com/user-attachments/assets/c8231a0e-1d71-4251-ba47-9ccb91885c1d" />

8. Locate 104.53.222.103 and select Add as Filter to further explore the connection. 


A single log is displayed about a network connection detected between 172.16.4.4 and 104.53.222.103. 


9. Examining this connection by scrolling down to the message section of the log as seen in Figure 28.2-4 below:


<img width="1888" height="793" alt="image" src="https://github.com/user-attachments/assets/9063e31f-965f-4929-ba7c-e0adc2e060c4" />

From this message, the image C:\Users\tammy.wall\Downloads\stream-installer.exe is identified as the initiator of the connection. This indicates an internal device opened a connection to this device via a file on the system.


To further identify connections from the remote host, a filter can be used to show if any other connections were established containing that IP. 


10. Remove the current filter and apply the following filter to view any logs containing the remote IP:
agent.type: winlogbeat AND 104.53.222.103



The only log displayed is the one found from the previous search. This indicates that this IP was only used to establish connection to this host. However, the attacker could have established further communications by using their connection to 172.16.4.4, or could have altered their IP address for certain attacks. 


A key element of the message is from the stream-installer executable. To view activity resulting from this connection, create a filter to see if a similar connection was used.


11. Apply the following filter to see any other logs containing the stream-installer executable:
agent.type: winlogbeat AND “stream-installer.exe”



12. Expand the first log and identify the destination and host IPs.  


13. Identify the IP that belongs to eng-wkstn-3. This connection illustrates that the victim box connected to the device 172.16.2.5 on the network with the same malicious file stream-installer.exe. 


14. Locate the filter file.target and select Visualize to view the full names of the values. Analyze the results. 


15. Select Back to navigate to the discover Kibana page.


16. Enter the following filter to include searching for the discovered executable:
agent.type: winlogbeat AND “stream-update.exe”



17. Analyze the new search results for additional devices. Select destination.ip from the Filter menu to view destination addresses.


The address appears similar to the same external IP address found earlier, 104.53.222.103. This is another external address being called to by the executable. 


18. Select the host.ip filter in the left menu to view connected devices, as shown in Figure 28.2-5 below.

<img width="495" height="624" alt="image" src="https://github.com/user-attachments/assets/4619dc33-b384-4eef-8e67-0f38b5fc663f" />


The previous IP from eng-wkstn-3 is present as 172.16.4.4. The new IP 172.16.3.3 is associated with the host bp-wkstn-2. This workstation is shown to be communicating with the 104.53.222.92 address. Further examination of the logs from this search show that no other connections were created to other workstations involving the suspected processes. 


This portion of the investigation shows the scope of the attack

<img width="1089" height="669" alt="image" src="https://github.com/user-attachments/assets/8168cc0f-df7b-40d5-9e52-16a357485ac7" />


------------------

Gather Threat Intelligence
The scope of the breach has been identified. The devices involved were quarantined and images have been provided to the CPT for analysis. 

﻿

Use Volatility to analyze the eng-wkstn-3 memory image, extract initial malware and secondary malware, and perform malware analysis in Cuckoo.

﻿

Workflow
﻿

1. Log in to the VM cuckoo-hunt with the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Right-click the Evidence folder on the Desktop, and then select Open in Terminal.

﻿

The profile of the memory image in evidence, memdump.mem, needs to be identified. The imageinfo command returns this value, but the command can take up to ten minutes to complete. 

﻿

In order to save time, the imageinfo command output is displayed in Figure 28.2-6 below:


<img width="2048" height="683" alt="image" src="https://github.com/user-attachments/assets/f73a5222-ae3c-4af2-b76f-b9d883ae3395" />

4. Run the following command to identify processes from the memory dump image using the profile Win10x64_14393:
vol.py psscan -f memdump.mem --profile=Win10x64_14393



5. Search the output and determine if the files identified in the previous Kibana analysis are running. 


6. Analyze the psscan output, as seen in Figure 28.2-7 below, and identify the PID of processes stream-update. and stream-install: 
<img width="2048" height="627" alt="image" src="https://github.com/user-attachments/assets/744ba4df-3301-4ea0-8407-fc0bfe27d84c" />

7. Run the following command to perform a scan of the full path of stream-update. using PID 1740:
vol.py cmdline -p 1740 -f memdump.mem -–profile=Win10x64_14393



The output confirms this is the same executable found running in Kibana.


8. Run the following command to perform a scan of the full path of stream-install using PID 4328:
vol.py cmdline -p 4328 -f memdump.mem -–profile=Win10x64_14393



Again, the output confirms that this is the same executable found in Kibana.


9. For further analysis, the process must be extracted to identify malicious activity. Use the following commands to extract the process to the Extracts folder:
vol.py procdump -p 4328 -u -f memdump.mem -–profile=Win10x64_14393 –-dump-dir=Extracts/



10. Use Cuckoo to analyze extracted files for malware. Open a Terminal window and run the following command:
cuckoo web



11. Open Mozilla Firefox and navigate to the following address:
localhost:8000



12. In the Cuckoo web browser, select Submit A File For Analysis.


13. Navigate to /Desktop/Evidence/Extracts and select executable.4328.exe.


14. Select Analyze.


15. Once the task is finished, the file status should change to Reported. Select executable.4328.exe to review the analysis summary.


The file displays a threat score of 6.2 out of 10 due to numerous signs of malicious behavior.


The behaviors identified in the sandbox, shown in Figure 28.2-8 below, indicate that the file is a packer with a callout to a remote.

<img width="1779" height="519" alt="image" src="https://github.com/user-attachments/assets/0170006e-830c-4f27-8a06-cedb6c38c818" />

17. For the stream-update.exe file, perform Step 10 to Step 13. This file has already been extracted to the /home/trainee/Desktop/Evidence/ folder. 


Use the Cuckoo report to answer the following questions



------------------------

Reporting Threat Intelligence
Creating a report of an incident is a thorough process. Many organizations have specific criteria for what must be included in an incident report. 

﻿

Creating an Incident Report
﻿

The Cyber Warfare Publication (CWP) 3-33.4 explains reporting requirements for Cyber Protection Teams (CPT). CPTs report through their Operational Control (OPCON) chain of command. All actions taken by CPTs are reported to the U.S. Cyber Command (USCYBERCOM), Joint Force Headquarters–Department of Defense Information Network (JFHQ-DODIN), and the network commander. Reports are shared with other organizations, when possible, as a courtesy regarding situational awareness. 

﻿

According to the CWP 3-33.4, reports must include the following details:

Root cause of issues
Indicators of Compromise (IOC)
Malware observed, identified, or discovered
Detection techniques and observables
Actions taken to address the issue
Impact to the supported mission
In the private sector, a similar approach is applied. However, reports made in the private sector vary by organization, and may require additional details about an incident. Additionally, private sector reporting may be subject to regulations or common practices that result in public disclosure of the incident. 

﻿

Using Incident Reports
﻿

After a report is created, a comparison can be made to determine if the activity is attributed to threat actor groups, or Advanced Persistent Threat (APT) groups. When behavior of the attacker matches or is similar to the known behavior of APTs, this information must be added to the report. 

﻿

Well-supported organizations have an IRT to respond to incidents. All details of discovered malware must be directly reported to the organization’s IRT. When reporting to the IRT, any details that can lead to further damage in the organization must be relayed immediately. 

﻿

For example, if a defensive analyst is analyzing malicious activity on a quarantined host and discovers activity of the threat actor pivoting to other devices on the network, those devices may also need to be quarantined. This activity should be reported to the organization’s IRT. Interactions with the IRT should be continuous throughout the investigation.
+


--------------

### CDAH-M28L3-Eradicate Threats and Restore Connectivity ###

Containment, Eradication, and Recovery
The IR life cycle consists of four phases:

Preparation
Detection and Analysis
Containment, Eradication, and Recovery
Post-Incident Activity
﻿Figure 28.3-1 displays these four phases of the continuous IR life cycle:


<img width="2500" height="1253" alt="image" src="https://github.com/user-attachments/assets/77a044c8-c5b7-4f8a-83bd-c8309803bb3d" />


When Cyber Protection Teams (CPT) are not actively responding to an incident, they are in the Preparation phase of IR. In this phase, CPTs maintain readiness through deliberate mission planning, preparation, execution, and assessment. A CPT’s work in IR is intended to supplement a local organization’s network defenders. When CPTs arrive onsite, they enter the Detection and Analysis phase by conducting their own Mission Analysis (MA). A CPT begins the Containment, Eradication, and Recovery phases of IR only after the operation has been approved, in accordance with the processes and tasks determined during the earlier phases of IR. This lesson addresses this third phase. 


Procedures Performed on Compromised Hosts


In the Containment, Eradication, and Recovery phase, procedures are reactive in nature, as an incident has occurred and hosts are compromised. Procedures in this phase are designed to prevent the spread of the adversarial presence in the network. Such procedures are performed directly on the compromised hosts and include isolating the hosts from the operational network (removing all network connectivity and placing in a sandbox environment), removing all adversarial presence (removing all malware and indicators associated with the incident), and returning the hosts to the operational network (verifying the adversarial presence is removed). The adversary can infect hosts using various methods. During this phase, analysts may be required to perform a wide range of tasks. Some tasks may include removing executable (.exe) files, registry keys, network connections, and user accounts. When the procedures in this phase are complete, the hosts are no longer compromised and may return to the operational network.



---------------


Analyze a Compromised Virtual Machine
Scenario
﻿

An incident has occurred within the network. Recently, remote service application malware was found operating on VMs within the network. When executed, the malware initiates a Remote Access Trojan (RAT) where code is executed on the infected VM remotely. The incident is contained within the win-admin VMs located in the Information Technology (IT) subnet of the network. The win-admin VMs are used by IT administrators and contain large amounts of sensitive information regarding the organization’s IT infrastructure, mission, and users. 

﻿

Upon detecting the malware, the IR team quickly enacted the Containment, Eradication, and Recovery phase of the plan. The Containment portion of the phase was completed by removing and isolating the infected VMs from the operational network. To discover artifacts and functionality of the malware, dynamic analysis was completed. Table 28.3-1 provides the findings of the dynamic analysis: 

﻿
<img width="2500" height="2235" alt="image" src="https://github.com/user-attachments/assets/b249b575-5074-4a60-8fbd-aa4148c2a43a" />


The Containment portion of the IR plan is complete. The IR team has removed and isolated all infected VMs from the operational network and has moved to the Eradication portion of the phase, where the VMs are analyzed for malicious artifacts. Any artifacts found are removed. 


Assist the IR team by accessing the win-admin-2 VM and identify locations where the eradication needs to occur. Not all findings listed on the attached Incident Response Findings document may be currently present on the win-admin-2 VM.


Workflow


1. Log in to the VM win-admin-2 with the following credentials:
Username: Trainee
Password: CyberTraining1!



2. Analyze the VM, and identify artifacts on the VM. Answer the following question.



--------------------


Identifying Threats
The VM win-admin-2 includes the following findings.

﻿

Malicious Executables and Applications
﻿

dc.exe is found within the C:\Users\trainee\Downloads directory. Figure 28.3-2 confirms that the dc.exe file found is a Remote Service Application


<img width="500" height="649" alt="image" src="https://github.com/user-attachments/assets/6b269a0d-e10e-4c79-bb62-3aec60db0b33" />

The DarkComet-RAT-5.3.1-master folder, containing the DarkComet application, is located as a hidden folder within the C:\Program Files directory.


Microsoft Defender SmartScreen


Microsoft Defender SmartScreen protects against phishing or malware websites and applications and against downloads of potentially malicious files. By disabling SmartScreen, one of the host’s first lines of defense is removed. Figure 28.3-3 displays Check apps and files “Off”:

<img width="402" height="350" alt="image" src="https://github.com/user-attachments/assets/f5a9f533-2221-422a-97c9-d3eeaae42ac6" />


RDP


Remote Desktop Protocol (RDP) allows for remote connections to the host. The RDP setting is available via System settings. The setting is useful for administrators and engineers but can also be maliciously leveraged by the adversary. The Enable Remote Desktop setting should only be “On” for known reasons and expected work. Figure 28.3-4 displays RDP “On”:

<img width="514" height="352" alt="image" src="https://github.com/user-attachments/assets/28c93231-4012-4e60-a911-ff2b94b80d40" />




---------------------


Eradicate Threats
Complete the steps in the following workflow to eradicate threats that have been identified on the VM win-admin-2.

﻿

Workflow
﻿

1. Log in to the VM win-admin-2 with the following credentials:

Username: Trainee
Password: CyberTraining1!
﻿

2. Complete the eradication portion of the win-admin-2 VM by completing the following tasks:

Delete dc.exe and the DarkComet-RAT-5.3.1-master file and directory.
Set the Check apps and files setting to “On” within Windows Defender SmartScreen.
Set the Enable Remote Desktop setting to “Off.”

Once the tasks in Step 2 are complete, the threats on the VM have been eradicated.

-------------

Recovery
During the Recovery portion of the Containment, Eradication, and Recovery phase of the IR life cycle, procedures focus on confirming and validating the completion of each task in the Eradication phase. Procedures are performed directly on the compromised host during Recovery and may include analyzing the host for any unidentified adversarial presence, confirming removal of all adversarial presence, and enabling connectivity to the operational network. When the procedures in this portion of the phase are complete, the host no longer contains adversarial presence and may return to the operational network.

﻿

Aid Recovery with Sysinternals
﻿

The Windows Sysinternals suite allows for quick and efficient monitoring, managing, and troubleshooting of processes within the Windows Operating System (OS). Sysinternals was installed on the compromised VMs to aid in IR efforts. Access the win-admin-2 VM, and, using Sysinternals, check for any remaining adversarial presence.

﻿

Workflow
﻿

1. Log in to the VM win-admin-2 with the following credentials:

Username: Trainee
Password: CyberTraining1!
﻿

2. Access Sysinternals at C:\Users\trainee\Desktop\SysinternalsSuite. 

﻿

3. Open Autoruns64, and let Autoruns64 scan for 3 minutes.

﻿

4. Analyze the data contained within Autoruns64, and review the data for any use of DarkComet and associated .exe files. 

------------------


Additional .exe File
Figure 28.3-5 shows the Autoruns data that reveals the IMDCSC.exe file associated with the DarkComet RAT:

<img width="1929" height="165" alt="image" src="https://github.com/user-attachments/assets/875cb3c6-41fa-4ea3-a8d9-e8dff64699d5" />

The IMDCSC.exe file is executing out of HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run within the registry. IMDCSC.exe is typically found within the Documents folder of the host and is used by applications for remote access. IMDCSC.exe does not have a visible window and is started by the entry in the registry. IMDCSC.exe is able to record keyboard and mouse inputs, manipulate other programs, and monitor applications.

<img width="1920" height="831" alt="image" src="https://github.com/user-attachments/assets/77ff7875-b8a6-4110-a8c1-8f6b567c195f" />
<img width="1088" height="459" alt="image" src="https://github.com/user-attachments/assets/db4487ab-9a8c-4804-a358-59c332b17085" />

--------------

Scheduled Task
Figure 28.3-6 shows the Autoruns data that reveals the IMDCSC.exe file associated with the \RSA scheduled task:

﻿<img width="1547" height="122" alt="image" src="https://github.com/user-attachments/assets/d9765d2c-32b0-434c-ad7f-4643c236924d" />

The scheduled task allows for an additional layer of persistence on the compromised host. The registry entry and scheduled tasks both allow the IMDCSC.exe file to start on the host.


Summary


With the aid of the Sysinternals suite, the compromised win-admin-2 host recovery efforts were examined. Through the use of Autoruns, an additional .exe file and subsequent persistence techniques were discovered. Each of the new adversarial components must be removed from the VM. Once the components are removed and their removal is verified, the VM may be returned to the network.

-----------------


Return from Isolation
Scenario
﻿

Continue aiding in the IR efforts. Consider the list of facts uncovered in the previous two exercises. A security baseline is a list of components that must be removed for the host’s return from isolation. Table 28.3-2 contains the secure baseline for all other hosts in the incident:


<img width="3335" height="3559" alt="image" src="https://github.com/user-attachments/assets/cc074e42-eecf-4029-b16c-39888af4b118" />


Table 28.3-3 contains Windows PowerShell cmdlets that allow for quick access to components found in Table 28.3-2. Table 28.3-3 contains only components where PowerShell speeds up access to components. Although this is possible with PowerShell, some components are easier to access through their settings location.


<img width="1600" height="823" alt="image" src="https://github.com/user-attachments/assets/ece52e12-fd55-4d23-adf7-a1a9291bf2e3" />


With the aid of Windows PowerShell and Sysinternals, evaluate the win-admin-3 and win-admin-4 VMs associated with the incident for their readiness to return from isolation by completing the next two exercises. 


Workflow


1. Log in to VM win-admin-3 with the following credentials:
Username: Trainee
Password: CyberTraining1!



2. Review and validate each component of the security baseline for the removal of adversarial presence. Answer the following question.



-------------


Security Baseline
The VM win-admin-3 includes two of the security baseline components and is not ready to be removed from isolation. All adversarial presence on the host has not been removed. Figure 28.3-7 displays the RDP setting “On” within Windows Settings

<img width="502" height="394" alt="image" src="https://github.com/user-attachments/assets/723ecc3c-b6ea-4340-840e-6fcef279b087" />


Figure 28.3-8 displays the output from Autoruns64. Although the dc.exe file was removed from the host, the \RSA scheduled task is still present on the VM


<img width="2043" height="206" alt="image" src="https://github.com/user-attachments/assets/fd7a3668-139f-4570-a417-033c015bd965" />



--------------


Further Analysis
Continue the analysis with VM win-admin-4.

﻿

Workflow
﻿

1. Log in to VM win-admin-4 with the following credentials:

Username: Trainee
Password: CyberTraining1!
﻿

2. Review and validate each component of the security baseline to validate the removal of adversarial presence. Answer the following question.
<img width="1413" height="742" alt="image" src="https://github.com/user-attachments/assets/23a47b4e-e6f5-4cde-8086-9eaa3d8bd420" />
<img width="1123" height="577" alt="image" src="https://github.com/user-attachments/assets/ca17b3e7-0f6e-46c1-9afd-fa82d4c5f4bd" />

-----------------


Further Assessment Summary
Summary
﻿

The DarkComet-RAT-5.3.1-master folder is found hidden on the VM win-admin-4. The use of the dir -force cmdlet quickly identifies the folder within C:\Program Files, as shown in Figure 28.3-9:

<img width="502" height="209" alt="image" src="https://github.com/user-attachments/assets/520c9480-d749-4266-8186-fac0ecb8dfdd" />

The DarkComet-RAT-5.3.1-master folder is empty. Although the folder does not contain any files, it must be deleted prior to the host’s removal from isolation.


------------------



### CDAH-M28L4-OPSEC Considerations in IR Processes ###

OPSEC and Incident Response
OPSEC is the process of protecting sensitive information against adversaries, as shown in Figure 28.4-1 below. 

﻿

Suppose malware was discovered on a device in a network. The functionality and origin of the malware is unknown. Maintaining OPSEC throughout the phases of IR is a priority because it allows the mission and operating environment to function without further compromise.

﻿

For example, malware can contain sophisticated capabilities, making it highly contagious to other devices that can easily compromise critical information on the network. 

﻿

Analysts must ensure that any devices found with malware are quarantined and isolated from the network. The analyst should return devices to operation only when the malware is eradicated and the incident is fully resolved. 

﻿

The five steps, or phases, of the OPSEC process are as follows: 

Identify critical information
Assess the risk
Analyze threats
Analyze vulnerabilities
Perform countermeasures

<img width="2500" height="1465" alt="image" src="https://github.com/user-attachments/assets/08633d72-6741-42af-8c89-307560c4b107" />

1. Identification of Critical Information
In the first phase, critical information is identified, defined, and recorded. Examples of critical information include, but are not limited to, the following: domains, Internet Protocol (IP) addresses, subnets, computer names, physical addresses, and Personal Identifiable Information (PII). 


2. Analysis of Threats
In the second phase, physical and virtual threats are identified. Facts such as who, what, where, when, why, and how are considered at this stage. Organizations must analyze threats by the level of impact on operations, assets, or individuals, and the likelihood of those threats occurring. 


3. Analysis of Vulnerabilities
In the third phase, an analysis of both internal and external weak points is conducted. The weak points are areas of the networks that may be exploited by adversaries. Decision makers must be honest and clear about the organization's components and configurations that may be vulnerable to attack. External components must also be analyzed during this stage. External components that are not directly controlled by the organization may include third-party software and contractors. 


4. Assessment of Risks
In the fourth phase, each portion of the organization's infrastructure is evaluated in terms of risk and exposure to the mission. Management must create a clear risk strategy that defines each level of risk and the amount of risk they are comfortable handling.


5. Application of Appropriate Countermeasures
In the final phase, a comprehensive countermeasure strategy is synthesized as a result of all previous stages. The selected strategy protects critical information, mitigates threats, patches vulnerabilities, and minimizes risk. With the strategy in place, IR personnel are able to quickly and accurately address the incident while maintaining as much OPSEC as possible.


-------------------


Enacting the IR Plan and Maintaining OPSEC
As shown in Figure 28.4-2 below, when an IR plan is put into action, compromised devices must be isolated, and threats must be eradicated


<img width="2500" height="588" alt="image" src="https://github.com/user-attachments/assets/a26da076-913e-4ca8-a354-522ade800c46" />

Isolation of Compromised Devices


The IR team must quickly remove compromised devices from the network. The longer the compromised devices remain on the network, the likelihood for further infection increases. Network backups of devices and Virtual Machine (VM) snapshots may be activated and used during this time. Compromised devices must be placed in a sandbox environment, which is an environment that is isolated from all other networks. The sandbox environment allows analysts to investigate the incident, conducting static and dynamic analysis of any malware.


Eradicating Threats


The IR team must accurately remove all adversarial presence from compromised devices. Compromised devices may have an adversarial presence in the form of malware. The malware must be statically and dynamically analyzed to record its artifacts, functionalities, and capabilities. The IR team produces a checklist once analysis is completed. The checklist identifies how the malware is removed and defines parameters that allow for a safe return of devices to the network. 


IR Recovery Checklist


Checklists are used across all IR phases to verify tasks and configurations. Recovering from an incident includes the eradication of threats on compromised devices and returning the devices to the network to resume normal operations. A recovery checklist includes items such as tasks, activities, and configurations to be verified as complete prior to a return of the network. 


Figure 28.4-3 below, and attached, is an example of a Containment, Eradication, and Recovery checklist. The checklist contains overarching tasks, but since each incident is different, specific tasks and eradication methods may change. This example is not based on the NIST documentation and is a visual example only


<img width="2500" height="2379" alt="image" src="https://github.com/user-attachments/assets/39353771-07bc-408b-864d-b38c04384c37" />


--------------

Restoring Operational Capabilities
Scenario
﻿

An administrator operating on the win-admin-2 VM opened a link from an email. The email sender posed as a user of the network who was requesting administrative support. 

﻿

Shortly after the link was opened, a security analyst monitoring the network noticed a large amount of network requests originating from the win-admin-2 VM. While addressing the request of the email, the administrator logged on to the win-admin-3 VM, and selected the link on that VM also. As a result of the opening the link, both VMs were infected with malware. 

﻿

The win-admin-2 and win-admin-3 VMs are used by Information Technology (IT) administrators. Both VMs contain large amounts of sensitive information regarding the organization's IT infrastructure, mission, and users. The security analyst quickly realized what occurred, contacted the IR team, and the IR plan was enacted. 

﻿

The IR team quickly enacted the Containment, Eradication, and Recovery phase of the plan, and isolated the win-admin-2 and win-admin-3 VMs from the network. The security analyst watched the network closely for suspicious activity, such as additional spikes in network requests. 

﻿

The IR team conducted dynamic analysis of the malware and compiled the details of their findings, as seen in Table 28.4-1 below:

<img width="2500" height="1972" alt="image" src="https://github.com/user-attachments/assets/b03c9408-db7d-4ef1-8dc4-c26fc573ef00" />


The Eradication phase of the IR plan was completed, with IR personnel removing all adversarial presence on the isolated VMs. The IR team moved to the Recovery phase, where the VMs were verified as free of malware and any other adversarial presence. 


The IR team developed a recovery checklist, based on tasks completed during the Eradication phase, to aid in the return of the VMs to the network. The recovery checklist is found below in Figure 28.4-4. 


<img width="2500" height="1906" alt="image" src="https://github.com/user-attachments/assets/7ee2718b-7379-48b2-b14f-03ca540a2378" />


------------


Post-Exploit Recovery Errors
The Windows Sysinternals suite allows for quick and efficient validation of each of the components on the recovery checklist. Errors with the post-exploit recovery process are easily identified through use of applications such as Process Explorer and Autoruns. 

﻿

The two errors found on the win-admin-3 VM are as follows: 

Lazr.exe operating on win-admin-3

StartIT is a scheduled task on win-admin-3

Error One
﻿

Process Explorer (procexp64) provides a live snapshot of all of the processes running on the VM. At the top of the application, Lazr.exe is entered as a filter, as seen in Figure 28.4-5 below. On win-admin-2, when the filter is entered, nothing is returned. This confirms that Lazr.exe is not operating on that VM. 

﻿

Figure 28.4-5 below shows the output of the filter when entered on the win-admin-3 VM

<img width="1400" height="312" alt="image" src="https://github.com/user-attachments/assets/26d17e2e-b5e8-4cbc-8286-4bfb7f7b181e" />

The output of the filter confirms Lazr.exe is operating on the win-admin-3 VM.


Error Two


Autoruns (Autoruns64) provides a live snapshot on a variety of objects such as system extensions, toolbars, scheduled tasks, auto-start services, and registry entries on the VM. At the top of the application, Lazr.exe is entered as a filter, as seen in Figure 28.4-6 below. On win-admin-2, when the filter is entered, nothing is returned. This confirms that no objects related to the Lazr.exe malware are present on win-admin-2. 


Figure 28.4-6 below shows the output of the filter on the win-admin-3 VM

<img width="2048" height="1252" alt="image" src="https://github.com/user-attachments/assets/409a03cb-102b-4ed8-bfaf-da54819873be" />

The output of the filter confirms Lazr.exe is included in the StartIT scheduled task, operating out of the C:\Users\Public\Documents directory.


Summary


With the use of the Windows Sysinternals suite, an error in recovery operations was discovered on the win-admin-3 VM. Process Explorer was used to discover Lazr.exe operating on the VM. Further analysis with Autoruns confirmed the StartIT scheduled task is still present on the VM, referencing Lazr.exe in the C:\Users\Public\Documents directory. 


During recovery operations the Lazr.exe malware was not correctly removed from the C:\Users\Public\Documents directory. As a result, the scheduled task is still valid and executes when a user logs on. 


The win-admin-3 VM must remain in isolation until all adversarial presence is removed and its removal is accurately verified.
