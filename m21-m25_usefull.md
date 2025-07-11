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



Kibana doesn’t maintain a built-in list of `event.code` values because these codes are **defined by the data sources**—like Winlogbeat, Sysmon, Auditbeat, or custom logs—feeding into Elasticsearch. However, I can give you a **longer reference list** of commonly used `event.code` values across popular sources that show up in Kibana dashboards.

---

### 🛡️ Windows Security Event Codes (via Winlogbeat)

| Code   | Description                                 |
|--------|---------------------------------------------|
| 4624   | Successful logon                            |
| 4625   | Failed logon                                |
| 4648   | Logon with explicit credentials             |
| 4670   | Permissions on an object were changed       |
| 4688   | New process created                         |
| 4689   | Process ended                               |
| 4697   | Service installed                           |
| 4720   | User account created                        |
| 4722   | User account enabled                        |
| 4723   | Password change attempt                     |
| 4724   | Password reset                              |
| 4725   | User account disabled                       |
| 4726   | User account deleted                        |
| 4732   | User added to security-enabled local group  |
| 4768   | Kerberos authentication ticket requested    |
| 4769   | Kerberos service ticket requested           |
| 4776   | Credential validation                       |
| 4798   | User account enumerated                     |

---

### 🔍 Sysmon Event Codes (via Sysmon module)

| Code | Description              |
|------|--------------------------|
| 1    | Process creation         |
| 2    | File creation time       |
| 3    | Network connection       |
| 5    | Process terminated       |
| 6    | Driver loaded            |
| 7    | Image loaded             |
| 8    | CreateRemoteThread       |
| 10   | ProcessAccess            |
| 11   | File created             |
| 12   | Registry object added    |
| 13   | Registry value set       |
| 14   | Registry object deleted  |
| 15   | FileCreateStreamHash     |
| 22   | DNS query                |
| 23   | FileDelete               |

---

### 📁 Auditbeat / Filebeat Examples

These modules often use custom codes or reuse system-level identifiers:

| Code   | Description                              |
|--------|------------------------------------------|
| 1000   | Application error (Windows)              |
| 3003   | Custom alert from external tool          |
| 4001   | File integrity violation                 |
| 5002   | Unauthorized access attempt              |

---

### 🔔 Kibana Alerting Event Codes (from `.kibana-event-log` index)

These are used internally by Kibana’s alerting and actions plugins:

| Code              | Description                                      |
|-------------------|--------------------------------------------------|
| execute           | Rule executor ran                                |
| execute-action    | Rule scheduled an action                         |
| new-instance      | New alert instance activated                     |
| recovered-instance| Alert instance recovered                         |
| active-instance   | Alert instance is active                         |

You can find more examples and query templates in [Elastic’s Kibana Event Log Guide](https://www.elastic.co/guide/en/kibana/8.18/event-log-index.html) and the [ECS event field reference](https://www.elastic.co/docs/reference/ecs/ecs-event).

---

If you’re working with a specific module or want to extract all `event.code` values from your environment, I can help you write a Kibana query or script to do that. Just let me know what you're working with!












