. Using the *:so-* index, execute the following query in SOC:
event.code: 1102 or event.code: 104 or event.code: 517 



Event codes 1102, 104, and 517 indicate logs were cleared from the host.


Here is a summary of all content related to Kibana from the file m26-m30.md in the lukasaq/hack-class repository:

Kibana: Context and Use Cases
Kibana is referenced as a tool for visualizing, searching, and analyzing event and log data, particularly within the Elastic Stack (ELK Stack: Elasticsearch, Logstash, and Kibana). It is used in incident response (IR) workflows to investigate security incidents, track network activity, and analyze logs for evidence of compromise.

Key Workflows Involving Kibana

1. Investigating Malicious Cyber Activity (MCA)
- Kibana is used to view Sysmon events, analyze host/network activity, and correlate indicators of compromise (IOC) and tactics, techniques, and procedures (TTPs).
- Example workflow: Log in to Kibana, set a time window (e.g., Aug 2, 2022 @ 09:20:00.000 to Aug 2, 2022 @ 09:25:00.000), and analyze resulting data for suspicious files, executables, persistence mechanisms, and network connections.

2. Prioritizing Vulnerabilities
- Kibana is used to review network traffic associated with vulnerabilities such as MS17-010 (EternalBlue). Filters are applied for specific ports (e.g., destination.port: 445) and rules (e.g., ET EXPLOIT Possible ETERNALBLUE Probe MS17-010).
- Analysts use Kibana to identify events, determine if vulnerabilities were exploited, and assess the impact on hosts.

3. Comparing IT and OT Network Activity
- Kibana helps compare traffic between IT and OT devices. Queries like destination.ip: 172.16.3.2 (IT workstation) and source.ip: 172.16.80.10 with event.dataset.keyword: modbus (OT/PLC device) are used to identify protocol usage and abnormal connections.

4. Detecting Lateral Movement and Malicious Connections
- Kibana queries track connections between workstations and PLCs, revealing unauthorized access or pivoting.
- Example query: source.ip: 172.16.3.2 and destination.ip: 172.16.80.10 to find suspicious traffic from IT to OT devices.

5. Investigating Log Integrity and Host Compromise
- Kibana is used to identify and analyze log-clearing events (e.g., event.code: 1102 or event.code: 104 or event.code: 517), which may indicate attempts to cover malicious activity.
- Filters and columns are customized (e.g., agent.name, event.code, event.action) to pinpoint which hosts and logs were affected.

6. Analyzing Malware Attack Paths
- After enabling the Windows Event Log service (if disabled by malware), Kibana is used to analyze logs for attack paths, process creation events, and PowerShell activity.
- Example search: event.action: "Process Create (rule: processCreate)" and process.command_line: "powershell".

7. Scoping Breaches and Threat Intelligence Gathering
- Kibana is used to scope breaches by analyzing which devices communicated with malicious IPs or ran specific malicious executables.
- Filters based on user.name, agent.type, and executable file names (e.g., “stream-installer.exe”) help trace the spread of compromise across the organization.

8. Timeline and Forensic Analysis
- Kibana aids in establishing timelines of compromise, tracking when logs were cleared, when services were disabled, and when malicious processes were executed.

Example Kibana Queries and Filters from the File
- destination.port: 445  // SMB traffic
- rule.name.keyword: ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style)
- rule.name.keyword: ET POLICY Powershell Activity Over SMB - Likely Lateral Movement
- destination.ip: 172.16.3.2 // IT host traffic
- source.ip: 172.16.80.10  // OT/PLC traffic
- event.dataset.keyword: modbus // Filters for Modbus protocol activity
- user.name: tammy.wall  // Filters by user
- agent.type: winlogbeat AND “stream-installer.exe” // Finds logs related to a particular executable
- event.code: 1102 or event.code: 104 or event.code: 517 // Log clear events
- event.action: "Process Create (rule: processCreate)" and process.command_line: "powershell" // Finds PowerShell process creations

Kibana Columns and Fields Frequently Used
- agent.name
- agent.type
- event.code
- event.action
- event.dataset
- event.module
- log.level
- source.ip
- destination.ip
- message

Common Steps in Kibana Workflows
1. Log in to Kibana (with provided credentials)
2. Set the relevant time window for investigation
3. Select or add specific fields/columns to the view
4. Apply filters or KQL queries relevant to the investigation
5. Analyze returned logs and events for suspicious or malicious activity
6. Use visualization features (like dashboards or field summaries) to correlate findings

Summary
Kibana is used throughout the incident response process to:
- Investigate and visualize suspicious activity
- Correlate events across hosts and timeframes
- Detect lateral movement, exploit attempts, and log manipulation
- Support forensic analysis and timeline reconstruction
- Prioritize vulnerabilities and identify compromised assets

If you need more detailed step-by-step workflows for any specific Kibana scenario (e.g., prioritizing vulnerabilities, analyzing log integrity, or tracking lateral movement), let me know which one you’d like to see in full detail!
