looking for users added to  groups

given
The following query looks for event codes related to user group modification for the local Administrators group:

event.code:(4728 or 4732 or 4746 or 4751 or 4756 or 4761)

outcome

![image](https://github.com/user-attachments/assets/3257e023-6767-42f2-a03e-a66e62db9c77)


event.code:1 and process.command_line.keyword~ localgroup

outcome

![image](https://github.com/user-attachments/assets/8399310b-71e9-4b30-8501-ad3f23a1375d)


my way

![image](https://github.com/user-attachments/assets/c6f2a16d-ba04-418e-993f-b6ca2739d91f)





Run a query that shows any outbound connections from DC01 by entering the following in the field connection.local.responder:
event.dataset:conn AND source.ip : 172.16.2.5 and connection.local.responder: false | groupby destination.ip

![image](https://github.com/user-attachments/assets/fac34e8c-7f9f-42f7-b386-0bed4063b938)

does the same as last 2 filters just in one

• event.dataset:conn AND connection.local.responder: false AND (source.ip : 172.16.2.5 OR source.ip 172.16.2.6) | groupby destination.ip


4. Modify the query to search for inbound traffic for one of the domain controllers:
event.dataset:conn AND destination.ip:172.16.2.5| groupby network.protocol destination.port source.ip


 Modify the query from the previous lab as follows: 

  this query displays a series of outbound DNS to 172.16.8.4. Granted, any protocol can run over any port, but since that is the DMZ DNS server, there is a low chance that it is malicious. This traffic is expected.
  
event.dataset:conn AND source.ip:172.16.2.5| groupby network.protocol destination.port

Check whether the DC02 is the only machine with this traffic to the dmz-www host by focusing the query on the dmz-www system and that port with the following query:
event.dataset:conn AND destination.ip:172.16.8.5 AND destination.port: "47150"| groupby destination.ip network.protocol

Conduct a query for all inbound and outbound traffic to the host dmz-www: 
event.dataset:conn AND (destination.ip:"172.16.8.5" OR source.ip: "172.16.8.5")| groupby destination.ip network.protocol



When using an ‘OR’ with this tool, parentheses are required with the destination/source IP address fields otherwise source.ip: 172.16.8.5 is enough to satisfy the expression since it has equal priority as the arguments next to the ‘AND’.




















