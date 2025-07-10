Show event logs related to scheduled jobs by using the following search filter:
(event.code:"4701" or event.code:"4702" or event.code:"4703")


2. Show event logs related to the Microsoft firewall by using the following search filter:
event.code:"2004" or event.code:"2006"




Event code 2004 is related to the creation of a new firewall rule, and event 2006 is related to the deletion of a firewall rule.


The message field contains information related to the firewall rule. Included in the information are the rule name, rule direction, and protocol. The port number is included not here but, instead, in the winlog.event_data.LocalPorts field.


9. Discover recently executed programs by adding the following in the search field: 
agent.name:bp-wkstn-1 and event.code:1



10. Discover network connections and identify the programs that were executed and are associated with network activity by entering the following in the search field:
agent.name:bp-wkstn-1 and event.code:3



11. Discover files recently created by entering the following in the search field:
agent.name:bp-wkstn-1 and event.code:11

8. Search for recently executed programs to find the delivery method of the malware by filtering the logs with the following search query:
agent.name:"bp-wkstn-1" and event.code:"7"



The results of the search indicate that Outlook ran, then Microsoft Edge ran shortly afterwards. 


9. Identify and locate the downloaded file and its contents by entering the following query. 
agent.name:"bp-wkstn-1" and event.code:"15"
















