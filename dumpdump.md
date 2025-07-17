### CDAH-M30L1-Modify IR Tools ###

Analyzing IR Script Functionality
A Host Analyst on a CPT conducting malware triage often uses scripts to perform IR information gathering. Depending on the Operating System (OS), scripts may be written in different programming languages. PowerShell is typically used on a Windows system, whereas Python or Bash scripts are often used on Linux systems. A CPT may be unfamiliar with the full capabilities of a script and must be prepared to determine the script’s functionality and assess its viability for use in a particular situation, such as script automation. Some aspects of scripts are prohibitive to automation, such as mandatory user interaction during execution. When planning for automation, identification of scripts that require such interaction is necessary, and the CPT may need to determine a strategy to modify the script to allow for automation.

﻿

Python scripts often import other modules from libraries to add functionality to the script. For example, the module argparse is often imported to give the script advanced capabilities for handling command-line arguments and parsing different options passed to the script. 

﻿

During determination of a script’s functionality, the imported modules can provide clues for the capabilities that the script might have. Many modules are available for import, and online resources can be used to determine the functionality they provide. Table 30.1-1 provides a few examples of available modules


<img width="2500" height="1024" alt="image" src="https://github.com/user-attachments/assets/7347d8d2-fd9c-46ed-89a3-95d5344613a1" />



-------------------

Determine Capabilities and Functionality of IR Scripts
In the following lab, assess the functionality of Python scripts that are typical of those found in a toolkit used during IR information gathering, and discover characteristics prohibitive to automation.

﻿

Workflow
﻿

1. Open the Virtual Machine (VM) lin-hunt-cent. The login credentials are as follows:

Username: trainee
Password: CyberTraining1! 
﻿

2. Locate the Python scripts by navigating to /home/trainee/Desktop/Scripts.

﻿

3. Analyze the scripts in the folder to assess their functionality. Examine the script code and run the scripts in a terminal window to make the assessment.

﻿

Use this workflow to answer the following questions



----------------------


Benefits of Automating IR
Adding automation to IR scripts may be done in numerous ways, but the ultimate goals are to reduce analyst workload and add a level of assurance that nothing is missed. Scripts generally minimize the occurrence of errors when compared with manual examination of systems. Creating automated scripts allows the same checks and information-gathering tasks to be run across multiple systems simultaneously. Performing repetitive tasks becomes less cumbersome, and scripts can be remotely deployed to automatically gather and centralize key system information from many different systems. This reduces the time needed for remediation. 





As an example use case, script automation can be used for gathering information about bound Transmission Control Protocol (TCP) ports and their associated processes. Implementing automation to deploy an information-gathering script to remote systems, gather the information, and report back from remote locations to a centralized location significantly decreases the time to identify Indicators of Compromise (IOC) related to ports used or process names. 

﻿

Scripts already in the Host Analyst’s toolkit can be used as the starting point for the automated tasks. However, because specific details differ from one investigation to the next, the Host Analyst may need to make slight modifications or introduce new functionality to a script to collect the necessary information.



-----------

PowerShell Enhancements for IR
PowerShell provides many options and cmdlets that help support automation of IR tasks. This section reviews some of PowerShell’s scripting features and provides examples of making enhancements to PowerShell scripts, including the following:

Remote system access

Task repetition

Output formatting

Chaining efficiency

Remote System Access
﻿

PowerShell cmdlets usually default to running on the local system, but some can accept the parameter -ComputerName to tell the cmdlet to run on a remote system and gather the same information. Many cmdlets support this parameter, and an analyst can use it to quickly gather information across an organization’s network from a single workstation. The following command provides an example of collecting hotfix information from a remote system:

Get-HotFix -Description "Security Update" -ComputerName "hostname"
﻿

The Invoke-Command cmdlet can be used to run PowerShell code on a remote system and display the results locally. The following example runs the code between the curly braces to display established network connections on the remote system:

Invoke-Command -ComputerName "server1" {Get-NetTCPConnection -State Established}
﻿

From an automation standpoint, one drawback to running commands on remote systems is that the user is prompted to enter credentials for accessing the remote computer. User interaction may not easily be incorporated into automated scripts, but PowerShell allows the creation of credential objects that can be created and preserved. For example, at the beginning of a script, code may prompt for credentials from the user that all subsequent code in the script requiring authentication can then use.

﻿

Running remote commands in a live mission will generate logs and network traffic. It is important to coordinate with the other analysts on the team and take detailed notes. Otherwise, another analyst might misconstrue the team's own actions for malicious cyber activity (MCA). Additionally, configuration changes on a compromised host may alert the adversary to the team's actions.

﻿

Task Repetition
﻿

Iterating over multiple objects in PowerShell can be accomplished using ForEach or ForEach-Object. In the following example, ForEach is used to iterate over a list of hostnames read from a text file check_hosts.txt and gather hotfix information from each. The list of hosts is stored in a variable, and ForEach is used to step through the entries one at a time. 

$host_to_check = Get-Content -Path "C:\check_hosts.txt"
ForEach ($host in $host_to_check) {
    Get-HotFix -Description "Security Update" -ComputerName $host
}
﻿

This code can be written more concisely by passing the list of hostnames directly to ForEach-Object and using the PowerShell variable $_ to refer to the individual hostname:

Get-Content -Path "C:\check_hosts.txt" | ForEach-Object {
    Get-HotFix -Description "Security Update" -ComputerName $_
}
﻿

This type of object iteration is possible for many cmdlet outputs.

﻿

Output Formatting
﻿

Most PowerShell cmdlets output data to the console using a table format, just as if the output is piped to the Format-Table cmdlet.

﻿<img width="837" height="427" alt="image" src="https://github.com/user-attachments/assets/530cf6fe-fd13-4451-b3a0-f69536a84554" />

Figure 30.1-1 shows the default table outputs for the Get-Hotfix and Get-NetTCPConnection cmdlets. Some cmdlets, such as Get-Date, do not show a table by default. However, the output of Get-Date can be piped to Format-Table to force the output into a table, as shown in Figure 30.1-2


<img width="837" height="262" alt="image" src="https://github.com/user-attachments/assets/27d908ae-1a49-4bf5-90b5-1bf54f25cbd6" />


By piping output to Format-Table, data can be grouped by a particular column. Used in conjunction with the Sort-Object cmdlet, data can be organized in a more readable form. The following example code demonstrates this:
Get-Hotfix | Sort-Object Description | Format-Table -GroupBy Description



When it is necessary to send the output of cmdlets to a file, the two cmdlets Out-File and Export-CSV are useful, depending on the desired output format of the resulting file. For text output, Out-File is used, and for Comma-Separated Values (CSV) output, Export-CSV is used, as the following examples show:
Get-Hotfix | Out-File "C:\folder\data.txt"

Get-Hotfix | Export-CSV -Path "C:\folder\data.csv"



Chaining Efficiency


The output of a PowerShell cmdlet is typically an object that can be used to chain into other cmdlets and filter results. These chains can extend for multiple outputs. For example, consider the following command with each part of the chain shown in alternating normal and italicized text:
(Get-ADComputer -Filter 'operatingsystem -like "*server*" ').Name | 
Foreach-Object {Invoke-Command -ComputerName $_ {Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue}
 | Sort-Object PSComputerName | 
Select-Object PSComputerName, LocalPort, RemotePort, RemoteAddress}
 | Out-File C:\Temp\TCP_Conn.txt



In the first chain, the command queries the domain for servers that have the string server in their OS name. Those objects are piped to the next chain, which iterates over the list and remotely gathers the established TCP connections on each. Use of the modifier -ErrorAction SilentlyContinue allows the rest of the iterations to continue, even if an error occurs during the collection of information. This can be important for automation to ensure that the script is not disrupted by periodic errors that are not critical in nature. The results are further piped into subsequent chains to be sorted, and specific fields are pulled out of the output and stored in a local file


-------------


Modify a Python Script to Increase Automation Capability
Scenario: An analyst is investigating suspected infections of Linux systems. The malware is known to randomize the process name, but one characteristic of the malware is that the executable file that launches the malicious process is deleted from the file system after the process starts. The Python code in script3.py can be used as a starting point for creating an automated script that can be used for subsequent IR activities related to tracking down the malware.

﻿

The challenge is that the starting script is not yet suitable for automation. In its current state, the starting script requires user interaction during runtime, and it works on only a single process. To be effective, the modified script needs to examine all the processes on a system and identify which processes show indications that the process executable file has been deleted.

﻿

In the following lab, modify an existing Python script to improve its ability to be used in automated IR activities. Remove runtime user interaction requirements, and expand the scope of the script to examine all processes.

﻿

Workflow
﻿

1. Open the VM lin-hunt-cent. The login credentials are as follows:

Username: trainee
Password: CyberTraining1! 
﻿

2. Launch a terminal window, and navigate to /home/trainee/Desktop/Scripts.

﻿

3. To prepare for script modification, make a copy of the original script3.py file:

cp script3.py checkprocs.py
﻿

4. Open the new checkprocs.py script in an editor, and modify the script to remove user interaction and iterate over all processes rather than just one process. Comment out all code from line 22 to line 30.

﻿

5. Insert the following five lines of code, starting at line 32:

for subdir in os.listdir('/proc'):
    if subdir.isdigit():
        proc_id = int(subdir)
    else:
        continue
﻿

Figure 30.1-3 shows the changes that should be made to the new script



<img width="757" height="514" alt="image" src="https://github.com/user-attachments/assets/926d578e-ace0-4088-97e4-660afe74bb5d" />


6. Save the script, and test the modifications by executing the new script from a terminal prompt:
sudo ./checkprocs.py



NOTE: When prompted, use the sudo password CyberTraining1!


With these changes, the checkprocs.py script iterates over all processes and does not require the user to provide a Process Identifier (PID) number to examine. This is the first modification to making a script that is suitable for automation.


The next modification to be made is to identify processes whose executable files have been deleted. Prior to making those modifications to the script, determine how a process with a deleted executable can be detected. A copy of the system executable sleep is made and used to launch a new process. The process information is examined first, and then the corresponding executable is deleted. The process is reexamined to note the differences and make a determination of how to detect those processes in the script.


Workflow


1. From the terminal prompt, make a copy of the sleep binary, and execute the copied binary in the background with a large time argument. Make a note of the PID value displayed after running the executable in the background:
cp /usr/bin/sleep /tmp/testsleep

/tmp/testsleep 9999999 &



2. Run the script3.py script, and enter the PID of testsleep when prompted. Observe the output, delete the testsleep executable file, and re-run script3.py to check the difference in output:
sudo ./script3.py

rm -f /tmp/testsleep

sudo ./script3.py


<img width="723" height="201" alt="image" src="https://github.com/user-attachments/assets/1dcf7d33-da7e-4334-82eb-067ac8b3cdfd" />


The output after the second execution of script3.py displays the EXE value with the string label (deleted) appended after the executable name. That string can be used to limit the output of the checkprocs.py script to only those processes with deleted executables.


Continue modifications of the script checkprocs.py to identify only the processes that have had the executable deleted.


3. Modify the fourth line from the end of the script as the following:
    if pid_info and pid_info["exe"].split()[-1] == "(deleted)":



4. Comment out the final two lines of code:



<img width="764" height="139" alt="image" src="https://github.com/user-attachments/assets/24caf664-2fe5-4bbf-b240-ddb1552d5e09" />


5. Save the file, and re-run the newly modified script:
sudo ./checkprocs.py



The output shows the test process created above that had the executable file deleted. With those modifications, the checkprocs.py script now examines all the processes on the system and displays only those that meet the criterion of having had the executable for a running process removed. This script is rea dy for aut omated use  and can b e  further tail ored as needed to  meet addition al automation requirements




----------------------


### CDAH-M30L2-Create an IR Tool ###


Evaluating Incident Response Tasks for Automation
During an IR, analysts perform activities to investigate an incident and identify the malicious artifacts on one or more systems. Some tasks may be more challenging than others because they require laborious actions across multiple systems.

﻿

IR often starts by gathering initial information and expanding on what is found to guide further research. This can complicate an automated response because each subsequent task may depend on the findings of a previous task. However, there might be an initial starting point to begin the investigation, such as a suspicious file, process name, or date/time. Automating the investigation using those pieces of information is easier to accomplish because search items are known and can be programmed into the automation script.

﻿

According to the Cybersecurity and Infrastructure Security Agency (CISA) Cybersecurity Incident & Vulnerability Response Playbooks, IR includes four steps:

Preparation
Detection and Analysis
Containment, Eradication, and Recovery
Post-Incident Activity

Activities that make up the second and third steps — Detection and Analysis, and Containment, Eradication, and Recovery — provide opportunities for automation. Expanding IR activities to include multiple systems can complicate implementation of automation.

﻿

Detection and Analysis
﻿

Gathering Information
﻿

One of the first tasks in IR engagements is to gather information and gain situational awareness of the current state of the system. This may mean gathering specific information, such as acquiring a listing of the processes running on the system or performing a full system survey. In either case, information-gathering tasks are typically well suited to automation, especially if no decisions are being calculated based on the information gathered. However, if the goal is to gather information and take additional steps based on what is found, automation may be more difficult.

﻿

Traversing the File System
﻿

A common requirement for IR is to search a file system for files or directories based on specific characteristics, such as timestamps, owners, permissions, or hash values. This task is well suited to automation and can save significant time when compared to manual examination of the file system. However, performance considerations of the types of actions being done on a per-file basis can impact the time required to conduct the activity. For example, searching an entire file system for a specific filename is relatively quick compared with the laborious task of gathering an algorithmic hash value of each file based on the file’s contents.

﻿

Querying Databases
﻿

Analysts may need to access many types of databases during an investigation. On Windows, the Registry is an important source of information. Remote logging systems, such as Kibana or Splunk, may provide information about an event as well. Accessing these information sources can be automated but require the use of the Application Programming Interface (API) used by the remote database system.

﻿

Searching and Parsing Logs
﻿

System log files represent another key source of information. On Windows, that includes the Event Logs and other subsystem log files, such as the firewall logs. On Linux, many different log files exist, depending upon what has been configured on the system, most of which are plaintext log files. Performing searches of these logs can be automated. However, variance in log file formats may necessitate tailoring each automation script to the specific log being accessed. If the log is in binary format, it may not be easily automated without the use of parser utilities.

﻿

Containment, Eradication, and Recovery
﻿

Collecting Artifacts
﻿

The task of collecting, isolating, and hashing artifacts can often be automated. A difficult aspect of automating an artifact collection is making a determination of what should be collected. Once identified, automating actions taken on the artifact is relatively simple. An important consideration when automating the collection is ensuring that the system does not experience such resource issues as low memory or disk space. If the automated tasks blindly perform the activity without regard for resource availability, the target system might run out of resources.

﻿

Configuration Changes
﻿

Automating mitigation and removal of malicious activity is possible, but if the automation script must parse and make decisions on what to change, it may cause undesirable modifications to occur. When it comes to automation, tasks that are highly specific, such as going to a known file and modifying a set value within or removing a particular file, are more easily automated.


--------------------


Create an Incident Response Script in Python
In the following lab, read the scenario. Then complete the workflow steps to create a Python script that reads a text file of hashes and searches specific folders for matches. The script should report any matching hash with its associated filename and path.

﻿

Scenario
﻿

Indications of a user-level rootkit have been detected in various systems across an organization. The rootkit replaces different binaries on Linux systems, and a list of MD5 hashes for known malicious binaries has been collected. Host Analysts conducting IR are instructed to use the list to search systems and determine if any of the binaries are present. The list of file hashes is provided in a text file, with a single hash on each line.

﻿

Workflow
﻿

1. Open the Virtual Machine (VM) lin-hunt-cent. The login credentials are as follows:

Username: trainee
Password: CyberTraining1! 
﻿

2. Navigate to the folder /home/trainee/Desktop/Scripts.

﻿

3. Open the file checkhashes.py in a text editor.

﻿

The script already has modules imported and a function defined called md5(). The function accepts a string parameter containing the full path and name of a file and returns the MD5 hash for the file as a string.

﻿

In the following steps, locations for additional modifications to the script are identified in the script with labels (for example, MOD1, MOD2).

﻿

4. At location MOD1, add the following code to the script to store the command-line arguments: 

hash_list_file = sys.argv[1]
startpath = sys.argv[2]
﻿

The above code uses the imported sys module to quickly access the command-line arguments. The first argument is the filename containing the hashes for the search. The second argument is the path of the starting folder to begin the recursive search. By providing support for command-line options, the script is made more flexible for use in circumstances beyond the task at hand.

﻿

5. At location MOD2, add the following code to read the hash list from the file and store the hashes from it as a list in a variable to be used in subsequent code for hash comparisons:

hash_list = []
with open(hash_list_file) as fd:
    hash_list = fd.read().splitlines()
﻿

The above code creates an empty list variable and opens the hash file provided on the command line. It reads the entire file contents, splitting the contents along individual lines so that each hash from the file is stored as a value in the list.

﻿

The script needs to calculate the MD5 hash of each file examined. This can require significant time, depending on the total number of files. The analyst must consider the performance implications of iterating over many files and reading each one completely to calculate the hash. When deciding between iterating over the list of hashes and comparing those with each file or iterating over the files and comparing with the hashes, the latter option is the most efficient, as each file hash is generated only once.

﻿

6. At location MOD3, add the code to iterate over the files recursively, starting at the top-level folder provided on the command line:

for root, d_names, f_names in os.walk(startpath):
    for f in f_names:
        fname = os.path.join(root, f)
        f_hash = md5(fname)
        if f_hash in hash_list:
            print(f_hash, fname)
﻿

The imported os module provides a function to walk recursively through a directory and its subdirectories. A list of folders and files is retrieved each time through the loop, and the list of files in the directory is used in a loop to iterate through each file, generating its MD5 hash. The code checks whether the hash appears somewhere in the hash_list generated in the previous step. If a match is found, the hash and the filename are printed to the console.

﻿

7. Save all changes to the file.

﻿

A list of hashes to search for is provided in the file /home/trainee/Desktop/Scripts/hash_list.txt.

﻿

8﻿. Right-click in the Scripts directory and click Open in Terminal.

﻿


9. Execute the following scripts:

./checkhashes.py ./hash_list.txt /usr/bin
./checkhashes.py ./hash_list.txt /usr/sbin
﻿

Using the above script, the hash_list.txt file is provided as the first command-line argument, and the folders /usr/bin and /usr/sbin are provided sequentially as the second argument to be used as the starting folder. The top-level / folder could be used a starting point, but the execution time would be long.

﻿

The outputs should show any files in the two folders that have an MD5 hash matching anything listed in the hash_list.txt file. This script now allows a Host Analyst to quickly identify potential malicious files matching the provided list. The added support for command-line arguments can also be used to easily check other folders or use different lists of hashes.

﻿

Using this workflow, respond to the following questions.

﻿

Keep the VM lin-hunt-cent open, as it is used in the next lab


------------------------


Evaluate Incident Response Tasks for Automation
Some IR tasks leverage specialized tools or software, such as imaging of system memory or drives. Other tasks are aimed at gathering and analyzing information from different system resources, such as processes or log files. Similarly, some are better suited for script automation than others.

﻿

In the following lab, consider a scenario in which an analyst is conducting an investigation on a system for which they have had no previous access. Decide which IR tasks should be done manually, without automated assistance, and which are more suitable for automation.

﻿

The VM lin-hunt-cent should still be open from the previous workflow. If it is not open, log in to the VM using the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

Workflow
﻿


1. Launch a terminal window, and run the following command to elevate the privileges to root:

sudo su -
﻿

Using the root shell, the first activity is to investigate reports of an unusual bound Transmission Control Protocol (TCP) port 3600 on the system.

﻿

2. Run the following commands to launch a root-owned shell and find the process that has bound the port:

netstat -natp
PID=$(netstat -natp | grep 3600 | awk '{ print $7 }' | cut -d'/' -f1)
﻿

The identification (ID) number for the process in question is now stored in the environment variable $PID.

﻿

3. View the process details in the process list, navigate to the /proc folder for the process, and discover the exe value to locate the process executable:

ps -ef | grep $PID | grep -v grep
cd /proc/$PID
ls -l exe
﻿

The executable is located in the /tmp/... folder, which is an unusually named hidden folder.

﻿

4. Run the following commands to navigate to the hidden folder and view the folder contents:

cd /tmp/...
ls -l
﻿

The file of interest is an executable named s1eep. (Note the use of the numeral 1 rather than the letter l in the filename.)
﻿

﻿

5. Using the Process Identifier (PID), run the following command to identify any systemd startup configuration files for the process. (The space between the = and $ characters is required.)

ps -o unit= $PID
﻿

The output shows that a systemd service file named display-client.service is associated with the suspicious process.

﻿

6. Show information about the systemd service by running the following command:

systemctl status display-client
﻿

This information can be used to search for other files on the system that may have been modified at the same time. It can also be used to search for account activity during that time.

﻿

7. Run the following command to examine the account logon activity:

last
﻿

The output of the command shows that the account backup logged on at about the same time as the timestamps of the executable file and the service activation.

﻿

Using the above workflow, answer the following questions.

---------------

Automating File System Searches
One of the most common automated tasks performed during an IR investigation involves using known information to perform searches across a file system for similar or related artifacts. The timestamps from known malicious artifacts are often used to find such artifacts. The goal is to use a sufficiently narrow search to return a manageable list of artifacts for further review. A reasonable starting point is to search for all files modified during the same date and within an hour of the known artifact’s modification time. Searching using only the file’s time, or searching for all modified files within the same month, likely returns many matches unrelated to the malicious file


-----------------


Comparing Tasks
During an investigation, some tasks are too complex to reasonably automate without significant time-prohibitive effort. Additionally, tasks that are potentially disruptive to the system, especially in ways that inhibit or disrupt the investigative process, should not typically be automated. As previously discussed, searching across a file system using known information is a good case for automation. However, automating a task that terminates processes without careful review should be avoided. Furthermore, scripts written for automation should avoid requiring repeated manual interaction from the user.

