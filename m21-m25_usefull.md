Here is a formatted list of all event codes mentioned in the file, organized by their source, with their descriptions:

---

### 🛡️ Windows Security Event Codes (Winlogbeat)

| Code   | Description                                 |
|--------|---------------------------------------------|
| 4624   | Successful logon                            |
| 4625   | Failed logon                                |
| 4648   | Logon with explicit credentials             |
| 4670   | Permissions on an object were changed       |
| 4688   | New process created                         |
| 4689   | Process ended                               |
| 4697   | Service installed                           |
| 4701   | Scheduled task created                      |
| 4702   | Scheduled task updated                      |
| 4703   | Scheduled task deleted                      |
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

### 🔍 Sysmon Event Codes

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

### 📁 Auditbeat / Filebeat Example Codes

| Code   | Description                              |
|--------|------------------------------------------|
| 1000   | Application error (Windows)              |
| 2004   | New firewall rule created                |
| 2006   | Firewall rule deleted                    |
| 3003   | Custom alert from external tool          |
| 4001   | File integrity violation                 |
| 5002   | Unauthorized access attempt              |

---

### 🔔 Kibana Alerting Event Codes

| Code              | Description                                      |
|-------------------|--------------------------------------------------|
| execute           | Rule executor ran                                |
| execute-action    | Rule scheduled an action                         |
| new-instance      | New alert instance activated                     |
| recovered-instance| Alert instance recovered                         |
| active-instance   | Alert instance is active                         |

---

### Other Event Codes (from search/filter examples)

| Code | Description                                    |
|------|------------------------------------------------|
| 7    | Image loaded (Sysmon)                          |
| 15   | FileCreateStreamHash (Sysmon)                  |

---

If you need these grouped differently or want further explanation for any code, let me know!
