




Here are all the workflows extracted from the file m31-m35.md. Each workflow is shown with its relevant steps, exactly as described in the document:

---

### CDAH-M31L1-Identify and Contain Malicious Activity

**Workflow: Analyze Hosts for Malicious Activity**
1. Log in to the VMs it-maint-0 and ls-wkstn-3 using the following credentials:
   Username: trainee  
   Password: CyberTraining1!
2. Using Table 31.1-1, analyze both VMs to identify whether either has been infected by the malware.
3. Answer the next set of questions to start the initial examination.

---

**Workflow: Identify Additional Artifacts from Malicious Activity**
1. Within ls-wkstn-3, review the registry for any persistence mechanisms placed by the malware.
2. Answer the next set of questions to continue the examination.

---

**Workflow: Implement Containment**
1. Log in to the VM ls-wkstn-3 using the following credentials:
   Username: trainee  
   Password: CyberTraining1!
2. Right-click the Windows Start icon on the toolbar and select Command Prompt (Admin).
3. Select Yes in the dialog box with the prompt Do you want to allow this app to make changes to your device?

---

**Workflow: Remove Network Connectivity for Containment**
1. In the Command Prompt (Admin), disable the interface Ethernet0.

---

**Workflow: Verify Changes for Containment**
1. Verify the network interfaces have been disabled by executing the following command:
   netsh interface show interface

---

### CDAH-M31L2-Preserve Evidence During IR

**Workflow: Evaluate Data Integrity**
1. Open the Virtual Machine (VM) ls-wkstn-3. The login credentials are as follows:
   Username: trainee  
   Password: CyberTraining1!
2. Using the Windows PowerShell cmdlet Get-FileHash, generate MD5 hashes for evidence files. Use the following format, replacing {FILENAME}:
   Get-FileHash {FILENAME} -Algorithm MD5
3. Verify the timestamps included in the Chain of Custody document.

---

**Workflow: Acquire a Forensic Image**
1. Open FTK Imager. Select Yes when prompted Do you want to allow this app to make changes to your device?
2. In FTK Imager, select File > Create Disk Image…
3. In the Select Source window, select Logical Drive, and select Next.
4. In the Select Drive window, select C:\ - [NTFS], and select Finish.
5. In the Create Image window, under Image Destination(s), select Add…
6. In the Select Image Type window, select E01, and select Next.
7. In the Evidence Item Information window, enter the following information:
   - Case Number: FN2187
   - Evidence Number: 1
   - Unique Description: Image of ls-wkstn-3
   - Examiner: trainee
   - Notes: <leave empty>
8. In the Select Image Destination window, enter:
   - Image Destination Folder: E:\
   - Image Filename: ls-wkstn-3_image
   - Image Fragment Size: 1500
   - Compression: 6
   - Use AD Encryption: <leave unchecked>
9. Select Finish.
10. Select Start to begin the creation of the image. Imaging may require up to 20 minutes.

---

### CDAH-M32L1-Strategize Threat Mitigation

**Workflow: Develop a Threat Mitigation Strategy**
1. Log in to the Virtual Machine (VM) win-hunt using the following credentials:
   Username: trainee  
   Password: CyberTraining1!
2. Confirm the marked files are present on the system by opening a Command Prompt and navigating to:
   - C:\Users\trainee\Downloads\mailbox_cleaner.html
   - C:\Windows\Temp\sjuKKE82234.bin
3. Log in to the VM lin-hunt-cent:
   Username: trainee  
   Password: CyberTraining1!
4. Confirm the marked file is present by opening Terminal and navigating to:
/opt/j8UHjdye45
5. Log in to the VM sift:
   Username: trainee  
   Password: CyberTraining1!
6. Confirm the marked file is present by opening Terminal and navigating to:
/opt/adWE9034

---

### CDAH-M32L2-Neutralize Threats

**Workflow: Scripting to Neutralize Threats**
1. Log on to win-dev VM with the following credentials:
   Username: trainee  
   Password: CyberTraining1!
2. Open PowerShell ISE as an Administrator.
3. Select New Script and enter the following text:
   ```
   $hosts = Get-Content -Path C:\Hosts\Hosts.txt
   $Result = ForEach ($hosts in $hosts)
       { Invoke-Command -ComputerName $hosts {Get-ChildItem "C:\Users\Public\Documents\forge.py"}}
   $Final = $Result | select PSComputerName | ft -auto -wrap
   $Final
   ```
4. Run the script. Review the output.

---

**Workflow: Removing Files with PowerShell**
1. Log on to win-dev VM with the following credentials:
   Username: trainee  
   Password: CyberTraining1!
2. Open the Hosts.txt file at:
   C:\Hosts\Hosts.txt
3. Modify the Hosts.txt file to only include the compromised hosts cdah-wrks0 and cdah-wrks2.
4. Save and close the Hosts.txt file.
5. Open PowerShell ISE as an Administrator.
6. Select New Script.
7. Enter the following script:
   ```
   $hosts= Get-Content -Path "C:\Hosts\Hosts.txt"
   foreach ($onehost in $hosts)
     {
           Remove-Item -Path "\\$onehost\c$\Users\Public\Documents\forge.py" -Force -Recurse
              }
   ```
8. Run the script.

---

**Workflow: Modifying the Registry Remotely**
1. Log on to cdah-wrks0 VM:
   Username: trainee  
   Password: CyberTraining1!
2. Open Registry Editor and access:
   Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\DriverUpdate
3. Log on to win-dev VM:
   Username: trainee  
   Password: CyberTraining1!
4. Open Command Prompt as Administrator.
5. Enter the following cmdlet:
   REG DELETE \\cdah-wrks0\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\DriverUpdate
6. When prompted to permanently delete all values under the registry key, enter Yes.
7. Open the cdah-wrks0 VM, open Registry Editor, and access the key path above.
8. Repeat Step 5 for cdah-wrks2:
   REG DELETE \\cdah-wrks2\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run\DriverUpdate

---

### CDAH-M33L1-Host Firewall

**Workflow: Create Host Firewall Rules**
1. Log in to the VM ubuntu20:
   Username: trainee  
   Password: CyberTraining1!
2. Open a Terminal and escalate privileges to root:
   sudo -s
3. Display the rules per direction by entering:
   iptables -S
4. Display the rules as a table:
   iptables -L
5. Clear all existing rules:
   iptables -F
6. Allow a single host to connect over SSH:
   iptables -A INPUT -p tcp --dport 22 -s 199.63.64.51 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
   iptables -A OUTPUT -p tcp --sport 22 -d 199.63.64.51 -m conntrack --ctstate ESTABLISHED -j ACCEPT
7. Block all incoming ICMP:
   iptables -A INPUT -p icmp -j DROP
8. Block all incoming FTP:
   iptables -A INPUT -p tcp --dport 21 -j REJECT
9. Block all outgoing traffic from 10.10.64.154:
   iptables -A OUTPUT -s 10.10.64.154 -j DROP
10. Display rules to ensure they match expected output.

---

**Workflow: Assess Host Firewall Rules on Linux**
1. Log in to the VM kali-hunt:
   Username: trainee  
   Password: CyberTraining1!
2. Open a Terminal and change to root:
   sudo -s
3. Scan the host Ubuntu to verify open ports:
   nmap -sV 199.63.64.154
5. Attempt SSH connection with netcat:
   nc 199.63.64.154 22
6. Attempt to ping for ICMP:
   ping 199.63.64.154
7. Attempt FTP connection:
   nc 199.63.64.154 21
8. View ports on private IP:
   nmap -sV 10.10.64.154
9. Attempt SSH on private IP:
   nc 10.10.64.154 22

---

**Workflow: Analyze Host Firewall Logs**
1. Log in to the VM kali-hunt:
   Username: trainee  
   Password: CyberTraining1!
2. Open Firefox and select the bookmark Discover - Elastic.
3. Log in to Elastic:
   Username: trainee@jdmss.lan  
   Password: CyberTraining1!
4. Set the date range for the activity.
5. Filter results by enabling log.file.path and Message.
6. Examine SSH activity with a query.
7. Filter logs to focus on a single host.

---

### CDAH-M33L2-Elastic Stack as a SIEM

**Workflow: Create a Prebuilt Dashboard**
1. Open the VM kali-hunt:
   Username: trainee  
   Password: CyberTraining1!
2. Open a web browser, log in to Elastic:
   Username: trainee@jdmss.lan  
   Password: CyberTraining1!
3. Select the hamburger menu > Dashboard.
4. Search for Sysmon, select Security Onion - Sysmon.
5. Set the time range.

---

**Workflow: Create a Custom Dashboard**
1. Return to the hamburger menu, select Dashboard, Create Dashboard.
2. Select Create Visualization.
3. Enter query:
   agent.name:"uws" and "Failed password" and "sshd"
4. Select and drag message.keyword to the center pane.
5. Change visualization to Table.
6. Save and Return to Dashboards.
7. Select Create Visualization, enter:
   process.command_line:*
8. Select and drag process.command_line, change to Donut.
9. Adjust values and options.
10. Save and Return to dashboard.
11. Drag the donut next to the table.
12. Hover to display command line counts.
13. Save, name dashboard IR Dashboard, enable Store time, Save.
14. Share > Permalink > Copy Link.

---

### CDAH-M33L3-Email Threats

**Workflow: Discover Threats Through Email**
1. Log in to the VM win-hunt:
   Username: trainee  
   Password: CyberTraining1!
2. Open Outlook to view Gabriel's unread emails.
3. Select first email, subject Unusual Sign-in Activity Detected.
4. Select the link in the email.
5. Exit browser, return to Outlook.
6. Right-click email, select Message Options, review internet headers.
7. Exit Message Options.
8. Select second email, subject Account Details.
9. Open attachment report.zip.
10. Open report.csv.
11. Open Google Security Report pop-up.
12. Select OK.

---

### CDAH-M34L1-Log Wrap Up

**Workflow: Identify Security Issues: Part 1**
1. Log in to corenet-wks0 VM:
   Username: trainee  
   Password: CyberTraining1!
2. Open Windows Event Viewer as Administrator.
3. Navigate to Windows Logs > Security.
4. Filter Current Log for specified time frame.
5. Determine if attacker cleared logs.

---

**Workflow: Identify Security Issues: Part 2**
1. Open corenet-wks0 VM:
   Username: trainee  
   Password: CyberTraining1!
2. Open Windows Event Viewer as Administrator.
3. Select Applications and Services Logs > Microsoft > Windows > Sysmon > Operational.
4. Filter logs for specified time frame.

---

**Workflow: Security Improvements and Recommendations**
1. Log in to corenet-wks0 VM:
   Username: trainee  
   Password: CyberTraining1!
2. Open Windows Event Viewer as Administrator.
3. Select Applications and Services Logs > Microsoft > Windows > TerminalServices-RemoteConnectionManager > Admin.
4. Check log entry for RDP.
6. Open Command Prompt as Administrator.
7. Enter command to check for update.exe.
8. Test YARA rule against file.
9. Open meterpreter.txt.
10. Open HxD as Administrator, open update.exe.
11. Search for each text string in meterpreter.txt.

---

**Workflow: Finalizing Security Analysis**
1. Log in to corenet-wks0 VM:
   Username: trainee  
   Password: CyberTraining1!
2. Open meterpreter.txt file, remove line $s2 = “.exehll”, save.
5. Open Command Prompt as Administrator.
6. Enter command to identify malware.
7. Note identified malware.
8. Check if host is feeding logs to SIEM:
   sc query winlogbeat

---

### CDAH-M34L3-Risk Mitigation Plan

**Workflow: Create an RMP**
1. Log on to cdah-wks0 VM:
   Username: trainee  
   Password: CyberTraining1!
2. Open TIA System 626 Threat Assessment Report.pdf from:
   C:\Users\trainee\Desktop\Threat Assessment\TIA System 626 Threat Assessment Report.pdf
3. Analyze the report to answer questions and create an RMP.

---

These are all the workflows explicitly listed throughout the file. Let me know if you want any specific workflow expanded or described in more detail.






















































