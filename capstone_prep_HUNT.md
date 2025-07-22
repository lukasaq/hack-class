As seen in Figure 35-1 and Figure 35-2 below, run the following command to see a list of processes:
python3.7
python3.7 vol.py -f /home/trainee/Downloads/memory.dmp windows.pstree

 vol -f /home/trainee/Downloads/memory.dmp windows.pstree
<img width="1387" height="321" alt="image" src="https://github.com/user-attachments/assets/78038a0a-70bc-4e7c-999e-a90b800e76b0" />
<img width="1461" height="322" alt="image" src="https://github.com/user-attachments/assets/9a99c662-2fae-40f5-b3b0-d1146046057e" />
The powershell.exe process is a child process of Excel because it has a Parent Process Identification (PPID) of 7312.


Run windows.cmdline to see the command line, as shown in Figure 35-3 and Figure 35-4 below:

vol -h
<img width="902" height="530" alt="image" src="https://github.com/user-attachments/assets/7b87d01d-6575-4532-ab0c-228cc9c83116" />

vol -f /home/trainee/Downloads/memory.dmp windows.cmdline
<img width="1101" height="281" alt="image" src="https://github.com/user-attachments/assets/58059c52-87f8-4e44-8056-4e648e57e690" />
<img width="1883" height="452" alt="image" src="https://github.com/user-attachments/assets/397697c1-4852-402b-9f83-41e183142dd2" />

There are three powershell.exe processes with base64 encoded command lines.



-------------------

scan file for .xls because EXCEL is what started powershell.

vol -f /home/trainee/Downloads/memory.dmp windows.filescan | grep '.xls'

<img width="1124" height="214" alt="image" src="https://github.com/user-attachments/assets/f5730844-7841-4ce3-b9e0-f7386b9b0c07" />


To see which files were opened during the time of the memory capture, run the following command: 
python3.7 vol.py -f /home/trainee/Downloads/memory.dmp windows.filescan > filescan.txt



Once the filescan plugin finishes running, examine the results. 


Filter the results to the first eight characters of the Excel.exe process virtual address. Search for the common file extension associated with Excel, “xls.”


Run the following command:
cat filescan.txt |grep '0xe60e4b'|grep 'xls'



As seen in Figure 35-6 below, the results show Realestate-247PalmerSt-FinanceDetails.xlsm. 

<img width="1134" height="212" alt="image" src="https://github.com/user-attachments/assets/a595a4ce-fbfd-4fec-b669-c5d99c2252c7" />

Alternatively, use the windows.dumpfiles plugin with the Excel.exe Process Identifier (PID), and ignore files with the .dll, .exe or .ocx file extension, as seen in Figure 35-7 below. 



<img width="1438" height="568" alt="image" src="https://github.com/user-attachments/assets/2a42f794-c48f-4a2e-abd5-16a5b51416c7" />

Alternatively, use the windows.dumpfiles plugin with the Excel.exe Process Identifier (PID), and ignore files with the .dll, .exe or .ocx file extension, as seen in Figure 35-7 below. 

vol -f /home/trainee/Downloads/memory.dmp windows.dumpfiles --pid <PID>

<img width="1438" height="568" alt="image" src="https://github.com/user-attachments/assets/d34be6c9-53db-42a2-b640-bc513b1ed56a" />



The file name is discovered.

---------------


































