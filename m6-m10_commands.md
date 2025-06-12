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

































































































