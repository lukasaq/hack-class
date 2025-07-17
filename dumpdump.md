

### CDAH-M26L1-NIST 800-61 IR Best Practices ###

NIST 800-61 Overview
Computer security IR is an important component of Information Technology (IT) programs. Establishing a successful IR capability requires effective and efficient planning and resources. NIST 800-61 was enacted to assist organizations in mitigating potential impacts to business operations and assets. The publication provides practical guidance on how to respond to degrading incidents. The guidelines in NIST 800-61 are independent of particular hardware, Operating Systems (OS), protocols, and applications while providing insight on the following: 

Establishing IR capabilities.
Maintaining situational awareness and handling of incidents using the IR lifecycle.


-----------


Incident Response Programs
An established IR plan, policy, and procedure are important to effectively and efficiently handle the task of mitigating a security breach. Rapid response when a security breach occurs is essential to minimize loss or theft of critical information and disruption of services within an organization. The mission partner should create a plan, policy, detailed list of actionable events, and Standard Operating Procedures (SOP) to prepare for an incident. The Cyber Protection Team (CPT) should review and use these documents to assist the mission partner during an IR.
﻿﻿

﻿

The following guidelines created by NIST describe policies, plans, and procedures related to IR:

﻿

Policies
﻿

IR policies differ in implementation, but each should contain variants of the following elements:

Purpose and goals.

Scope (who, what, and when).

Descriptions of possible IRs.

Definitions of team roles, responsibilities, and levels of authority.

Incident rating scale.

Organization chart.

Communication guidelines.

Plans
﻿

A formal, focused, and coordinated approach to responding to incidents can make the difference between a successful and failed event. The plan lays out the necessary resources and management support. A proper plan considers the following elements:

Company mission, objectives, and values.

Consent from leadership.

Communication methods. 

Correlation of risk and threat.

Scheduled road map with timeline of events.

SOPs
﻿

Procedures should be based on the IR policy and plan. This includes toolsets implemented, techniques used, and communication practices. These procedures should stem from company goal prioritizations and be used as a training and instructional baseline.

﻿

External Parties
﻿

Organizations often communicate with external parties regarding an incident. While maintaining appropriate OPSEC, the mission partner may find communication with the following parties helpful in mitigating attacks on the network:

Public Affairs office

Legal department

Management

Media

Law enforcement

Internet Service Providers (ISP)

Software vendors

CPT Roles and Responsibilities
﻿

Per Cyber Warfare Publication (CWP) 3-33.4, Cyber Protection Team (CPT) Organization, Functions, and Employment:

﻿

“If MCA [Malicious Cyber Activity] discovery and mitigation exceeds local network operators or local service provider expertise, capabilities, or capability, CPTs may respond to provide support conducting cyberspace defense actions, either remotely or by deploying to the affected location, or a combination thereof. A CPT’s role in reinforcing or augmenting local network defenders resides in the CPT’s execution of approved Joint Mission Essential Tasks (JMETs) by maneuvering dynamically to reconnoiter terrain in networks and systems and validate MRT-C [Mission-Relevant Terrain in Cyberspace] (or KT-C [Key Terrain in Cyberspace] if required) and MCA.”

﻿

NOTE: Bracketed material has been added above to define various acronyms.

﻿

CPTs respond to provide support to a mission partner during an IR scenario to perform four primary functions:

Hunt

Clear

Enable hardening

Assess

﻿<img width="1071" height="636" alt="image" src="https://github.com/user-attachments/assets/fcc16127-9154-4810-af35-e3ff928d7217" />
<img width="1125" height="630" alt="image" src="https://github.com/user-attachments/assets/b2a0afb1-fe35-4f44-9203-c5c763a37979" />
<img width="1079" height="658" alt="image" src="https://github.com/user-attachments/assets/1968712a-aae0-428f-8324-064cfea87484" />

-----------



Phases of the IR Lifecycle
The IR lifecycle consists of four phases, shown in Figure 26.1-1. The initial phase, Preparation, consists of establishing a trained CPT and analyzing available equipment within the Joint Deployable Mission Support System (JDMSS) kit based on locally protected network or system configurations. This is done to determine necessary hardware and applications based on mission scope and scale. Also, a set of controls based on the results of risk assessments is implemented to attempt to limit the number of incidents; residual risk persists after controls are inherited. The second phase, Detection and Analysis, is necessary to alert the organization about any incident that occurs. In the third phase, the incident can be eradicated by containing it and ultimately recovering from it. The final phase, Post-Incident Activity, consists of a generated report documenting the cause and cost of the incident as well as recommended hardening steps by the CPT to prevent future incidents. 



<img width="2500" height="1253" alt="image" src="https://github.com/user-attachments/assets/67476414-0318-4dd3-8855-630b8d49c623" />


------------------

Preparation
﻿

﻿

Sustaining CPT readiness includes deliberate planning, preparation, execution, and assessment, but CPTs are not intended to replace a supported organization’s local network defenders. Onsite CPTs complete their own Mission Analysis (MA) before determining any actions.

﻿

Per CWP 3-33.4:

﻿

“Once CPT MA is completed, available CPT forces are examined to determine CPT mission accomplishment capability. The scope of the proposed mission and other on-going CPT requirements factor into mission element and crew selection. Specifically, CPT leadership examines the team members’ experience, proficiency, and training levels, as well as administrative readiness status against the number of personnel required to complete the mission as determined during CPT MA. The scope of the terrain and operational-level mission completion date drive the number of personnel required. For example, a critical hunt and clear operation may necessitate twenty-four-hour-a-day coverage over a one week period and require more personnel than an enable hardening or assess mission with a longer completion deadline conducted during normal duty hours only. Once selected, personnel prepare for mission execution.”

﻿

IR methodologies emphasize preparation and ensuring that systems, networks, and applications are sufficiently secure. Preparing to handle and prevent incidents includes the following:

Information gathering: This involves promptly accessing available information, including network diagrams, contact directory, on-call information, network application and technology documentation, network baselines, and hashes of known good files in the mission partner’s network.

Coordination: This involves establishing an IR plan, cementing roles and responsibilities, and demonstrating an effective line of communication between the CPT and mission partner. There should be an issue-tracking system, smartphones, encrypted software, and a war room, all for the purpose of having secure communication methods on a separate medium from the location of the attack.

Checklists: Actions must be taken quickly during an IR. Checklists provide guidelines on steps to be performed to handle an incident. 

Mitigation plans: This includes determining supplies readily available for restoration and recovery purposes, such as clean laptops for analysis, a sandbox for testing, blank media discs, portable printers, clean OS images, and additional tools needed in conjunction with the CPT JDMSS kit.

---------------


Detection and Analysis
﻿

﻿

Threat-focused hunt operations illuminate known or unknown malicious cyber actors and determine MCA scope and purpose within the mission partner’s protected network or system. Hunting is the process of proactively and iteratively searching through networks to detect evidence of MCA to gain and maintain contact with an adversary and develop the situation. Network defenders and Cyber Security Service Providers (CSSP) should not rely on CPT hunting operations for threat detection. Passive incident detection and threat hunting operations can, and should, be conducted simultaneously. 

﻿

Hunt operations involve active reconnaissance and counter-reconnaissance on the mission partner’s supported network. The steps below correspond to the Preparation and Detection and Analysis phases of an IR lifecycle:

﻿

1. Gain and maintain situational awareness of the MCA.

2. Consult with Subject Matter Experts (SME) to determine methods and intent behind MCA.

3. Engage with mission partner CSSPs to assist with an IR plan.

4. Make a risk mitigation recommendation based on the benefits or consequences of continuing hunt operations versus initiating clear operations.

﻿

Executing proactive hunt operations requires consideration of, but is not limited to, the following:

Constantly evolving attack vectors; methods; or Tactics, Techniques, and Procedures (TTP).

Dwell time.

Risk to mission.

Available intelligence.

Attack Vectors   
﻿

Different types of incidents merit different response strategies. The following vectors provide a basis for defining more specific handling procedures:

External/Removable Media: Attacks from a removable media device, such as a Universal Serial Bus (USB) device or Compact Disc (CD), to execute malicious code on a vulnerable system. 

Attrition: Attacks employing brute force methods to compromise, degrade, or destroy  networks, systems, and services.

Web: Attacks executed from a website or web-based application (for example, Cross-Site Scripting [XSS] attacks).

Email: Attacks executed via email messages or attachments. 

Impersonation: Attacks involving the replacement of something benign with malicious intent (for example, Man-in-the-Middle [MitM] attacks, spoofing, Structured Query Language injection [SQLi]). 

Improper Usage: Incidents resulting from violation of organization policies by authorized users (for example, installation of file-sharing software). 

Loss or Theft of Equipment: The loss or theft of a computing device or media used by an organization.

Signs of Incident 
﻿

The most tedious part of an IR process is accurately detecting and assessing possible incidents. This includes determining if an incident has occurred and the type, context, and magnitude of the problem. Signs of incidents fall into two categories: precursors and indicators. Incorporating technologies that can flag malicious activity, such as antivirus software, Intrusion Detection Systems (IDS)/Intrusion Prevention Systems (IPS), and Security Information and Event Management (SIEM), is essential. 

﻿

Precursors
﻿

Precursors are signs of an attack prior to the attack’s occurrence. The best way to mitigate damages from an attack is to stop it before it occurs. If precursors are detected, an incident may be prevented by altering the security posture of the organization. Examples of precursors include the following:

Web server log entries indicate the use of a vulnerability scanner.

An outside notable threat states that the organization will be attacked.

Indicators
﻿

Indicators are signs that an attack is actively occurring against a network. Indicators are relatively common. Examples of indicators include the following:

An IDS alerts a buffer overflow attempt.

Host records display an auditing configuration change in logs.

Application logs display multiple failed login attempts from a remote system.

Analysis
﻿

CPTs should work diligently to analyze and validate each incident following a predefined IR plan. NIST recommends the following to aid in this process:

Create a network profile.

Understand the mission partner’s normal network behavior.

Have a log retention policy.

Correlate potential incidents with multiple network sources.

Keep all host clocks synced.

Create a network knowledge base.

Research information on unusual activity.

Collect additional data using packet sniffers.

Filter out insignificant data. 

Incident Documentation
﻿

All evidence about the status of the incident, such as system events, conversations, and observed changes in files, should be documented. The incident data should be safeguarded, as it contains sensitive information. 

﻿

Incident Prioritization and Notification
﻿

Each time an incident is discovered, a risk-based analysis must be considered and discussed with the appropriate personnel on any further actions that must be taken. Incident analysis can be broken down into three separate impact areas — functional impact, information impact, and recoverability impact — and the levels of threat of each. 

﻿

Functional Impact
﻿

Does the incident impact user productivity or system availability? Table 26.1-1 describes the four threat level categories of functional impact:

﻿
<img width="2500" height="1177" alt="image" src="https://github.com/user-attachments/assets/40ff2ed6-0e67-4e94-b374-ab3523e7e7d5" />


Information Impact


Could the incident result in the release of sensitive company or personal information? Table 26.1-2 describes the four threat level categories of information impact:

<img width="2500" height="1118" alt="image" src="https://github.com/user-attachments/assets/e02c4375-4c16-4f06-99d8-a66b5815bb06" />

Recoverability Impact


If possible, what resources would be required to recover from the incident? Table 26.1-3 describes the four required resource categories of recoverability impact:


<img width="2500" height="1028" alt="image" src="https://github.com/user-attachments/assets/ad2851e0-5527-42a3-ba74-22f501ab02d6" />



-------------------

Containment, Eradication, and Recovery
﻿

﻿

Once the Detection and Analysis phase is handled properly, the following is performed, corresponding to the Containment, Eradication, and Recovery phase as directed or tasked: 

﻿

1. Contain affected systems and networks simultaneously to prevent adversary repositioning.

2. Neutralize and eradicate adversary activities in each network or system.

3. Observe and characterize adversary behavior and TTP to enable follow-on operations (for example, enable hardening).

4. Enable recovery or restoration of affected systems and networks.

﻿

Containment Strategy
﻿

Strategies vary based on the type of incident, and a strategy should be created and documented for each major incident type. Criteria for determining the appropriate strategy include the following:

Potential damage to, and theft of, resources.

Evidence preservation.

Service availability.

Resources and duration needed to implement the strategy and provide an effective solution.

Effectiveness of the strategy.

Evidence Gathering and Handling
﻿

Evidence should be gathered according to procedures that meet all regulations. A detailed log should be kept for all evidence, including the following:

Details on who collected the information.

Where evidence was collected.

When evidence was collected.

Where and how evidence was stored.

Identifying Attackers
﻿

Identification of the attacking host(s) can be a time-consuming and futile process. It can prevent a CPT from achieving the primary goal of minimizing the impact to the mission partner’s network environment. Nevertheless, any information found could aid authorities in the capture or identification of the attacker. Methods for identifying attacking hosts are as follows:

Validating the attacking host’s IP address.

Researching the attacking host online.

Monitoring incident databases.

Monitoring attacker communication channels.

NOTE: When doing online open-source research of attacking hosts, use a non-attributable system while maintaining OPSEC.

﻿

Eradication and Recovery
﻿

Eradication and recovery are done in a phased approach so that remediation steps are prioritized. Eradication is done to eliminate components of the incident, such as deleting malware and disabling breached user accounts. In some cases, eradication is not necessary or is done in tandem with recovery efforts. During recovery, systems are restored to normal operation and hardening actions are initiated on known vulnerabilities to prevent similar incidents in the future. 


-----------

Post-Incident Activity
﻿

﻿

Post-incident activity involves learning and improving based on new threats, improved technology, and lessons learned. After an IR, the network should be in a more secure state. Maintaining a secure state means learning from mistakes and improving security posture, such as developing improved policies and procedures for future incidents. All collected actionable data is to be secured and retained for a period of time specified in record retention policies by the organization for legal proceedings. Post-mortem meetings should be conducted with all parties involved in the IR to contemplate lessons learned (objective and subjective data) during the IR lifecycle. 

﻿

Follow-up reports using collected incident data should be generated. This data can be put back into the risk assessment process, ultimately leading to the selection of additional security controls. The checklist in Table 26.1-4, reproduced from NIST 800-61, provides major steps to be followed in the handling of an incident:

<img width="1962" height="2500" alt="image" src="https://github.com/user-attachments/assets/c39c070b-f477-4d35-8f50-80935e604131" />

<img width="1087" height="650" alt="image" src="https://github.com/user-attachments/assets/d7e5ff0b-b344-4a89-9b07-ad4bc2c2ddac" />


--------------------

NIST Best Practices
Keeping the number of incidents reasonably low to protect the business processes of an organization is imperative. More incidents may occur if security controls are insufficient, and the IR team may be overwhelmed. As a result, slow and incomplete responses by the team may occur, negatively impacting the business process of an organization through more extensive network damage and longer periods of service and unavailability.

﻿

An IR team can play a key role in risk assessment and training by identifying gaps in the security architecture. The following provides an overview of primary recommended practices for securing systems, networks, and applications. 


<img width="2500" height="1194" alt="image" src="https://github.com/user-attachments/assets/aa3fba34-1dd7-47bd-ac66-efcaf8ba7ef5" />

Risk Assessments


Periodic risk assessments should be conducted regularly to identify critical resources within the organization to emphasize monitoring and response activities. An assessment determines what risks are posed by combinations of threats and vulnerabilities to systems and applications. Risks can be mitigated, transferred, or accepted. 


Host Security


All hosts should have auditing enabled and be hardened appropriately using standard configurations. Hosts should be configured to log significant security events and follow the principle of least privilege, granting users only the necessary privileges to complete authorized tasks.


Malware Prevention


Malware protection should be deployed at the host level (for example, server and workstation OS), the application server level, and the application client level. 


User Awareness and Training


Users within an organization should be aware of policies and procedures regarding appropriate use of networks, systems, and applications. By improving user awareness, the frequency of incidents should be reduced. 


----------

Use NIST Best Practices for Incident Response
An Administrator account within the mission partner’s network browsed to a web page that was hosted by a workstation located within the network environment. The Administrator account was present there from Aug 2, 2022 @ 09:20:00.000 to Aug 2, 2022 @ 09:25:00.000. The user downloaded and executed a file that resulted in suspicious activity on the host. 

﻿

For training purposes and resource limitations, a sandbox environment was created and the suspicious file was implanted and replicated on the Host Analyst machine.

﻿

Items of interest include the following:


Created files

Persistence mechanisms

Network activity


Complete the steps in the following lab to investigate the potential MCA and the resulting events using Windows Sysinternals and Kibana. 

﻿

NOTE: In a real event, the primary functions of an IR lifecycle —  Preparation, Detection and Analysis, Containment, Eradication and Recovery, and Post-Incident Activity — are conducted by the IR team.
﻿

﻿

Workflow
﻿

1. Log in to the Virtual Machine (VM) win-hunt using the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

The following steps align with the Preparation and Detection and Analysis phases of an IR lifecycle. 

﻿

2. Open the Process Monitor (Procmon64) shortcut located on the desktop. Select Run, and select Yes. 

﻿

Procmon is part of Windows Sysinternals and records live file system activity, such as process creations and registry changes. 

﻿

3. Minimize Procmon, and return to the desktop. Select Lab1.exe, located on the desktop. 

﻿

4. Close the malware notification:

﻿<img width="1272" height="632" alt="image" src="https://github.com/user-attachments/assets/2033693c-edf1-4a50-ae01-7a16116fa3a4" />


﻿

At this point in a real event, a Clear operation would be in effect, and the host in the mission partner’s network would immediately be contained and quarantined (for example, by disabling the Network Interface Card [NIC]) to prevent the MCA from propagating to other hosts. 


Malware protection should be deployed at the host level (for example, server and workstation OS), the application server level, and the application client level within a network environment. 


5. Return to Procmon. Select Filter on the menu task bar, and select Filter on the drop-down menu. In the Process Monitor Filter window that appears, select Process Name, and enter Lab1.exe as the search term. Select Add and OK. 


<img width="1487" height="852" alt="image" src="https://github.com/user-attachments/assets/fd5bb880-cfbd-452a-9455-99e0fcf13aa4" />


<img width="1180" height="724" alt="image" src="https://github.com/user-attachments/assets/60a3e5af-4f6a-438c-95a4-decec75118da" />

NOTE: If Add is not selected after inputting the filter, a prompt asks to add the filter. 


The events are now filtered to display the MCA. Specific files, connections, or processes that the application is accessing can now be analyzed. 


6. Scroll down the filtered output list, and analyze the results that display interactions with the registry, created file activity, and network connections. 


NOTE: Additional filters can be applied to Procmon, if needed, to assist with the output analysis. 


7. Close Procmon.


8. Open tcpview64, located on the desktop, to further analyze network connections from the MCA. Select Yes to open the application when prompted. 


TCPView displays detailed listings of all Transmission Control Protocol (TCP) and User Datagram Protocol (UDP) endpoints on a system, including local and remote addresses and the state of any TCP connections. 


9. In the TCPView search box, enter Lab1.exe to filter the network connections toward the MCA:  


<img width="1374" height="142" alt="image" src="https://github.com/user-attachments/assets/b8399fee-9966-4734-a2f5-1f1a4b40b3ed" />

The output shows that the application is continuously making connections to a remote IP address over a specific port. 


10. Make a note of the remote IP address and port. 


Another Windows Sysinternals tool, Autoruns, can be used to analyze and detect any persistence mechanisms that malware is using to survive on the infected host. To survive and evolve, malware must outlive a system reboot by creating a persistence mechanism, such as a scheduled task or specific run keys in the registry. 


11. Open Autoruns64, located on the desktop. Select Run to continue. If administrative rights are requested, select Yes.


The tabs located on the taskbar are the areas that Autoruns checks for persistence. 


12. Analyze the returned entries for anomalous activity. Once completed, close Autoruns. 


<img width="2050" height="852" alt="image" src="https://github.com/user-attachments/assets/73f7febe-919c-41ef-bf44-a6da0e9af57e" />


It is evident that the MCA creates a persistence mechanism by creating a specific run key in the registry. 


The Clear operation in an IR lifecycle can move forward, and the Host Analyst can use Kibana to correlate the MCA behavior with Indicators of Compromise (IOC) and TTPs. 


13. To view Sysmon events pertaining to the MCA, open Google Chrome, and select the Security Onion bookmark. Log in using the following credentials:
Username: trainee@jdmss.lan
Password: CyberTraining1!



NOTE: If the warning Your connection is not private appears, select Advanced, and select Proceed to 199.63.64.92 (unsafe). 


14. Set the time period of interest as Aug 2, 2022 @ 09:20:00.000 to Aug 2, 2022 @ 09:25:00.000, and select Update.


15. Analyze the resulting data. 


Look for the infected host(s) in the mission partner’s network, suspicious files that were created, executables run, persistence capabilities, and IPs or ports used for communication.

<img width="2048" height="962" alt="image" src="https://github.com/user-attachments/assets/fe32d915-26e6-4abd-a366-b6f9b765192f" />


Once the critical details of adversary behavior are discovered, Eradication (for example, deleting malware and disabling breached user accounts) and Recovery or Restoration, followed by Hardening actions on the infected host(s) within the mission partner’s network, can be performed. These actions are crucial to restore normal system operations.


Some Hardening actions are as follows: 
Propose network architecture changes to improve security and reduce risk.
Ensure unnecessary services are disabled.
Ensure that the latest patches are installed.
Audit installed software.
Enforce an audit policy.
Enhance security systems and logging.

Assessing post-incident activity is critical to an organization’s security posture, and all hosts should have auditing enabled and be hardened appropriately using standard configurations. Users within an organization should also be aware of policies and procedures regarding appropriate use of networks, systems, and applications and be given only the necessary permissions to conduct tasks. 


By following these procedures and conducting periodic risk assessments regularly to identify critical resources within an organization, the frequency of incidents is reduced. 


Answer the questions that follow. 

<img width="1133" height="694" alt="image" src="https://github.com/user-attachments/assets/76866370-2681-4750-ac77-b194bba9b7a2" />
<img width="1090" height="710" alt="image" src="https://github.com/user-attachments/assets/8c5ce722-69f6-40ca-adf1-931ab14e830d" />
<img width="1043" height="621" alt="image" src="https://github.com/user-attachments/assets/2bae75a0-9bf7-473b-8825-8d2969b96844" />
<img width="1055" height="732" alt="image" src="https://github.com/user-attachments/assets/98c4aa15-bbf2-4e2e-809c-d2f7eaac34a8" />
<img width="1096" height="654" alt="image" src="https://github.com/user-attachments/assets/7947d3b9-100e-42e9-918d-0bdcc1e0d361" />

----------------

IR OPSEC Considerations
OPSEC is the security and risk management process to ensure the protection of details and assets of an organization’s network environment. In IR, OPSEC is required to validate that the mission or operation of a mission partner’s network environment can function without being further compromised by MA, and the assets are not returned to operation until the incident at hand has been fully resolved and malware has been eradicated. 

﻿

Containment, eradication, and recovery methods while prioritizing, securing, and maintaining critical assets within the network environment to reduce the risk of further network compromise must be a primary focus. The most expedient efforts to restore the organizational operations to a minimum operating state must be applied. To reduce the risk of further network compromise, the following must be performed:

Information Gathering: Deployment of additional sensors may provide an adversary with critical information due to undesired monitoring and logging. Containment of infected machines before gathering additional information may be necessary.
Containment: Delaying containment of compromised hosts to gather additional information is risky and is a liability to the mission partner as it allows attacks to continue. Compromised hosts must be isolated and ensure that all affected systems have threats eradicated and capabilities restored before allowing operations to return to a normal state. 
Communication: Coordination with the mission partner is common during planning and up to execution, depending on the mission task. Hunt missions may result in minimal or no communication with the mission partner for OPSEC reasons. The internal team ultimately makes the operational decisions. 
Post-Incident Recovery: Recovery or restoration actions to reestablish security and defenses using verification checklists, as seen in Table 26.1-4, must be performed. In addition, observations must be collected, and security and defenses must be collected in preparation for future Defensive Cyber Operations (DCO). All of this must occur while prioritizing OPSEC. 
﻿
<img width="1144" height="672" alt="image" src="https://github.com/user-attachments/assets/eff04e09-e2e8-4d71-ba41-6dad1092c5c7" />
<img width="1111" height="713" alt="image" src="https://github.com/user-attachments/assets/074390ec-d905-41b8-a4d5-51ca03cc4e8e" />


-----------

### CDAH-M26L2-Identify Critical Systems and Vulnerabilities within Infrastructure ###

Critical Systems
An enterprise network is composed of hardware devices connected together through an intricate series of network links. Every configured device has the possibility of containing vulnerabilities. Network administrators attempt to mitigate the risks associated with these devices, however vast this task may seem. The vulnerabilities these devices emit are a weakness in architecture and provide a potential foothold for an adversary to gain access to a network and perform lateral movement to search for key data or assets. This risk is why cybersecurity teams must establish a complete and accurate view of all the critical systems that are part of a network, then attempt to address each vulnerability.

﻿

The following three tables define common critical network systems and the roles they play in the network. The tables describe why each system is critical and targeted and categorize them as follows:

Network Devices
Constructs
Applications

Network Devices

<img width="856" height="1600" alt="image" src="https://github.com/user-attachments/assets/bd58743f-d0ac-4012-a7f8-7ab1c870b052" />

Constructs

<img width="1600" height="615" alt="image" src="https://github.com/user-attachments/assets/53bc48fb-b4a1-40a4-ba42-b1909559cbd6" />

Applications


<img width="1581" height="1600" alt="image" src="https://github.com/user-attachments/assets/e76876a1-bc30-44bb-9d06-62fb6e9ca8dd" />


<img width="1110" height="599" alt="image" src="https://github.com/user-attachments/assets/b1040abc-1b71-4d42-b341-c086de0b7304" />

<img width="1004" height="638" alt="image" src="https://github.com/user-attachments/assets/c4ce2a8c-d385-4841-a398-62b3e45bcaab" />
<img width="1120" height="628" alt="image" src="https://github.com/user-attachments/assets/971adeb5-900d-4de0-9f3e-db53d4c8319e" />

------------------


Understanding Critical Devices and Associated Risk
Every military operation must follow an Intelligence Preparation of the Operational Environment (IPOE) process. The IPOE requires an analysis of enemy capabilities, possible courses of action, and a detailed analysis of Key Terrains (KT). KT are physical locations that may provide an advantage to an adversary. KTs are easy to identify on a map. Identifying key terrain provides valuable information on where to focus efforts to defend or attack a physical location. 

﻿

The level of analysis required for an IPOE also applies to cyberspace operations. The Joint Publication 3-12, Cyberspace Operations defines the term "cyberspace" as a "global domain within the information environment consisting of the interdependent network of Information Technology (IT) infrastructures, including the Internet, telecommunications networks, computer systems, and embedded processors and controllers." 

 

Key Terrains in Cyberspace (KT-C)
﻿

Cyber terrain is not always directly related to a physical location. Instead, cyber terrain may include physical mediums such as software, Operating Systems (OS), network protocols, virtual personas, and other computing devices. KT-C are considered physical nodes or data that enable or support mission execution. Adversaries may attempt to exploit, compromise, damage, or destroy various elements of KT-C. If an adversary inflicts damage to a particular area of the network or a particular component of infrastructure, the impact on the mission depends on the function of the network area or component. KT-C fall into three tiered categories that are based on the levels of impact any attack has on the Operational Environment (OE). This will be covered in greater detail in the next section. 

﻿

The United States Cyber Command (USCYBERCOM) Operational Guidance, Identification of Mission Relevant Terrain in Cyberspace, provides guidelines for Defensive Cyber Operations (DCO) team members working with cyber terrain. This guide requires the following components when defining cyber terrain, which include both logical and physical components:

KT-C: Any locality or area (physical or logical) where seizure, retention, or other specified degree of control provides a marked advantage in cyberspace to any combatant. 

Mission Relevant Terrain in Cyberspace (MRT-C): All devices, internal/external links, OSs, services, applications, ports, protocols, hardware, and software on servers required to enable the function of a critical asset.

Task Critical Asset (TCA): An asset so critical that its incapacitation or destruction would have a serious, debilitating effect on the ability of one or more Department of Defense (DoD) or Office of the Secretary of Defense (OSD) components to execute the capability or mission-essential task it supports. 

Defense Critical Asset (DCA): An asset so critical to operations in peace, crisis, and war that its incapacitation or destruction would have a serious, debilitating effect on the ability of the DoD to fulfill its missions. TCAs are used to identify DCAs.

Identifying terrain has a direct impact on a Cyber Protection Team (CPT) mission, when performing hunting, clearing, hardening, and assessing operations. After the CPT is assigned a terrain in which to hunt and operate, the threat hunter can filter data based on the types of systems and datasets available. Data requirements are driven by the analysis of potential threat actors that can target the mission partners' networks and the Tactics, Techniques, and Procedures (TTP) they employ. Identifying terrain, in turn, reduces the number of analytics necessary for the team to execute the mission objectives. The threat hunter can also filter for data on the identified MRT-C and KT-C to prioritize the required data collection. 

﻿

Understanding KT-C provides a distinct advantage over the adversary by allowing the analyst to focus on defenses for the network. For example, a Network Analyst knowledgeable of KT-C would be able to foil an adversary from further penetrating the vulnerable network by providing mitigating controls for identified weak security postures resulting from identified vulnerabilities supporting KT-C. CPTs are continually required to adjust and adapt to new adversaries or TTPs as KT-C constantly remains at risk. 

﻿

Critical Tiers
﻿

A network, its supporting infrastructure, and the various integrated applications can be prioritized into three tiers of critical assets, with respect to potential loss or damage severity. Adversaries attempt to compromise various elements of critical assets to exploit, compromise, damage, or destroy the network. Figure 26.2-1, below, describes the three tiers of damage or disturbance impact. If a tier is not assigned, this means the impact is low priority.

﻿
<img width="1667" height="834" alt="image" src="https://github.com/user-attachments/assets/8b5ad438-e92b-4fbb-bc87-b7a7a0f860f6" />


Tier 3 - Medium Priority


Tier 3 covers general data and applications. Compromise of these assets or information makes the organization subject to periods of degraded performance, but it does not destroy or corrupt data or halt business processes. Examples include data or services that, if lost, corrupted, or destroyed, can be recovered or restored with minimal impact on business processes.
 
Tier 2 - High Priority


Tier 2 covers important data and applications. Compromise of these assets or information makes the organization subject to serious damage and interrupts or degrades business processes. Examples include data that, if lost, corrupted, or destroyed, would have a serious impact on the organization or the essential applications or servers critical to that data. 
 
Tier 1 - Critical Priority


Tier 1 covers top value, critical, and essential data, applications, network services, and information processing. Compromise of such assets or information makes the organization subject to exceptionally grave damage and prevents critical business processes. Examples include any asset whose data compromise, corruption, or destruction has a devastating impact on the organization’s applications, critical network infrastructure, or data systems.
In Figure 26.2-2 is an example of a network map reflecting identified critical systems in a network environment and their associated terrain tiers. Table 26.2-4 displays the critical systems and their potential effects of compromise. 

<img width="2048" height="1654" alt="image" src="https://github.com/user-attachments/assets/3ec655fb-ed9d-43a9-912f-e10ef43b8e3a" />
<img width="1271" height="2048" alt="image" src="https://github.com/user-attachments/assets/7cae1cfe-a1a9-4ad8-ac00-6db547e40ac5" />


-----------------

Vulnerability Risk Levels
Vulnerabilities are identified by a Common Vulnerabilities and Exposures (CVE) number. This number generally consists of the four-digit year and a unique number identifier, such as CVE-2000-0001. Each CVE is assigned a score to represent its severity level. This score is based on the Common Vulnerability Scoring System (CVSS), which assigns a number between 0.0 and 10.0, where 10.0 is the most severe. Table 26.2-5, below, describes each level:

<img width="1668" height="1755" alt="image" src="https://github.com/user-attachments/assets/e4bc8764-feca-4f05-941a-467d4011a533" />

After risk levels have been identified, the organization should consider which devices on the network are critical assets of the greatest concern. Identifying these device criticality levels is part of the risk analysis process.


Assigning Risk Based on Risk Levels and Device Criticality


Analyzing the risk associated with a vulnerability and the criticality level of devices on a network provides a way to rank and prioritize risks to the organization. This process is risk analysis, which leads directly into patch prioritization. The risk analysis process shows how organizations identify the highest level of risk. Patches should be prioritized based on this analysis. 


Figure 26.2-3, below, provides a risk matrix for prioritizing vulnerability risk levels. This matrix is an example of the visualization an organization may use to determine the patches to prioritize for implementation, based on the availability of organizational resources. The figure suggests priority levels for associated vulnerabilities and devices using the following patterns and colors:
Minimal: Green, vertical stripes
Low: Yellow, horizontal stripes
Moderate: Orange, narrow diagonal stripes
High: Red, wide diagonal stripes
Extreme: Solid black

<img width="1667" height="834" alt="image" src="https://github.com/user-attachments/assets/74156e43-a43c-4725-a71a-feed77b1738f" />

Organizations may alter this matrix to better fit their businesses. For example, some organizations may consider all high- and critical-level vulnerabilities an extreme priority. Another factor of risk analysis is in determining risk likelihood. Risk likelihood considers the likelihood of a specific risk to occur. For example, on a network with many mitigating controls in place, a critical vulnerability may have such a small likelihood of occurrence that it may not need resources allocated for patching. In a thorough analysis, all risks are compared with the vulnerability level, criticality of the device, and the likelihood of the risk. All of this information factors into how an organization handles risks.


---------------

Common Exploits
Analysts who develop an in-depth understanding of common exploits are better equipped to implement effective defensive measures for securing critical systems from potential Malicious Cyber Activities (MCA). An exploit is any tool or technique that leverages a vulnerability to gain access to networks and systems. Adversaries frequently exploit vulnerabilities that have not been properly addressed. Exploits can either be either local or remote and affect three target groups: clients, web applications, and infrastructure. 

﻿

Local exploits target the system on which they are performed. This is usually a system that an attacker has already accessed. An example is executing the privilege escalation exploit DirtyCOW to gain root access on a system where the attacker already has user-level access. 

﻿

Remote exploits target a system other than the system from which they are performed. An example is EternalBlue, which sends malformed instructions to a remote Server Message Block (SMB) service to gain Remote Code Execution (RCE). A remote exploit is still remote even if it is performed on a localhost or a system where user-level access is already gained. For example, an attacker may gain user-level access to a machine and use that access to turn on SMB before using EternalBlue to elevate to the SYSTEM level account.

﻿

Exploits by Attack Style
﻿

Table 26.2-6, below, lists and explains common types of exploits by their attack style. This table also provides the vulnerabilities that each exploit targets and examples of real life exploits that can be classified under each type.

<img width="1234" height="2048" alt="image" src="https://github.com/user-attachments/assets/ef87500c-6a98-45c4-a440-2c428832665a" />


Exploits by Architecture


Exploits can also be classified by the architecture they target, such as the following:
Clients
Web Applications
Infrastructure
Client Exploits


A client exploit targets an individual machine or software instance. Workstations and software such as File Transfer Protocol (FTP), Java, and web servers may be vulnerable to client exploits. Software that runs on a server and is shared to a network may also be the target of a client exploit, in some cases. For example, if the exploit targets the software explicitly and results in access to the software or an underlying system. Infamous examples of client exploits include the following:
EternalBlue
BlueKeep
DirtyCOW


EternalBlue


EternalBlue (CVE-2017-0144) is a well-known remote exploit targeting the SMB service on Windows computers. The exploit leverages an input validation vulnerability in SMBv1, which was previously enabled by default despite having been superseded by SMBv2 and SMBv3 to support legacy systems. Although the exploit was patched after Windows 10 Version 1507, systems without the proper Windows Patches Knowledge Base (KB) are vulnerable. The attacker sends a specially-crafted packet to the service, which grants RCE. This access is SYSTEM level and represents a total compromise of the system through a vulnerable port such as Transmission Control Protocol (TCP) Port 445. 


BlueKeep


BlueKeep (CVE-2019-0708) is a memory-based remote exploit targeting the Remote Desktop Protocol (RDP) service on Windows 7 computers. The vulnerability exists in a pre-authentication mechanism by which clients negotiate aspects of the connection with the server. By requesting specific connection parameters, heap corruption occurs that allows for remote code execution at the SYSTEM level. Since this occurs pre-authentication, a username and password are not required. SYSTEM level access represents a total compromise of the system.


DirtyCOW


DirtyCOW (CVE-2016-5195) is a local race condition privilege escalation exploit targeting the copy-on-write mechanism in the Linux kernel. Using the right timing, the race condition allows the attacker to use the copy-on-write mechanism to make a non-writable file mapping writable. This file is then modified and compromised before it is executed. If this file runs with a greater privilege level than the user running it, for example, a Set User Identification (SUID) binary, it is used to run commands or other code as root. The most common payloads are commands to spawn a root-level system shell or a Remote Access Trojan (RAT) executed as root. 


Web Application Exploits


A web application is hosted by a server accessible by a web browser. This includes mobile applications that rely on web-based protocols and frameworks such as Hypertext Markup Language version 5 (HTML5), even if the applications are not presented as traditional websites. Web application exploits are different from exploits against web server software, such as Internet Information Services (IIS) or Apache. Exploits against web server software are considered client exploits. Web application exploits target the functionality of a web application through Structured Query Language (SQL) Injections or command injections. Web application exploits often focus on compromising information or gaining initial access to a network. Examples of web application exploits include the following:
Injection
ShellShock


Injection


The term "injection" is a catch-all descriptor for input validation attacks against web applications. The most common injection attacks are SQL injections and command injection, also called code injections or OS injections. An injection attack targets legitimate application functionality. The attack attempts to force the application to run unintended commands by exploiting oversights in the application's validation and sanitization of user-provided input. 


ShellShock


ShellShock (CVE-2014-6271) is a collection of security bugs in the Unix Bash shell that allow for command injection. The attack specifically targets Bash’s function export feature. This feature allows one Bash process to share scripts with the other Bash processes it executes.


Infrastructure Exploits


Infrastructure refers to anything that provides a service to a network. Attackers exploit infrastructure services to impact a broader scale of targets, rather than accessing targets individually. For example, Active Directory (AD) is a core part of Windows infrastructure. Attackers generally exploit AD to compromise or affect an entire network or large sections of a network. Even though an infrastructure exploit may communicate directly with a Domain Controller (DC), this doesn't mean the DC, itself, is the ultimate target. Other potential targets include services such as a Domain Name System (DNS), Dynamic Host Control Protocol (DHCP), and Link-Local Multicast Name Resolution (LLMNR). Some examples of infrastructure exploits include the following: 
Kerberoasting
SIGRed
Kerberoasting


Kerberos is an authentication service that relies on a ticketing system. A Service Principal Name (SPN) identifies Windows services. To enable authentication with Kerberos, each SPN must associate with a service account. A service account is an account specifically tasked with running a specific service. These accounts often inherently have high privilege levels because their services require it. 


To use these services, users request Ticket-Granting Service (TGS) tickets that allow them to use the service account to temporarily leverage a service. These TGS tickets use Rivest Cipher 4 (RC4) encryption. RC4 uses the service account’s hash as the private key for the encryption. The attacker downloads and saves these tickets as a file to brute force the hash offline. This hash then authenticates as the associated account. It is often trivial for attackers to compromise the Domain Administrator (DA) account or an entire network due to the privilege level of these service accounts.


SIGRed


SIGRed (CVE-2020-1350) is a memory-based exploit targeting the Windows DNS service WinDNS. In this exploit, an attacker sends requests to the victim's DNS server. The request is forwarded and resolved to a DNS server that the attacker controls. The victim DNS server then essentially becomes a client that the attacker forces to communicate with their server at any time. 


Due to a flaw in the way DNS handles overly large DNS packets, a specially-crafted packet has the capability to cause a heap-based overflow, resulting in RCE. Any payload delivered runs as the local SYSTEM account of the machine running the DNS server. This process generally results in a complete network compromise, due to the DNS and the privilege level of its service account.
<img width="1087" height="638" alt="image" src="https://github.com/user-attachments/assets/dd387dfa-ec77-408e-95f6-4120f8a8322b" />
<img width="1081" height="607" alt="image" src="https://github.com/user-attachments/assets/167c6f37-9c5f-4ce0-8a8a-67a10ee6a218" />


-----------------

Identify Vulnerabilities
In the following scenario, a Cyber Defense Analyst (CDA) is assisting a mission partner with prioritizing vulnerabilities associated with their critical IT infrastructure within the network environment. A network scan of the mission partner's network environment has been conducted using Assured Compliance Assessment Solution (ACAS). Multiple vulnerabilities were detected, placing critical IT infrastructure at risk to MCA. 

﻿

Identify Infrastructure Vulnerabilities
﻿

Use ACAS and the conducted scan to prioritize the critical IT infrastructure vulnerabilities within Elastic Stack. Recommend and mitigate gaps by enabling hardening of the critical IT infrastructure to improve security and reduce risk to MCA.  

﻿

NOTE: The mission partner's network map pinpointing the critical IT infrastructure has been provided as an attachment. 

﻿

Workflow
﻿

1. Log in to the Virtual Machine (VM) acas using the provided credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Open a Firefox web browser and select the bookmark Nessus.

﻿

NOTE: If a warning appears in the browser, select Advanced…, then select Accept the Risk and Continue. If prompted to log in, use the credentials from step 1.

﻿

3. From the left pane of the Nessus dashboard, select My Scans, then select Mission Partner's Network. 

﻿

The network scan of the mission partner's network environment displays numerous vulnerabilities associated with the critical IT infrastructure and their severity. The page for the selected network scan provides the following tabs, displayed in Figure 26.2-4, which provide additional information:

Hosts: Scanned hosts
Vulnerabilities: Vulnerabilities associated with the scanned hosts
Notes: Notes about the scan
VPR Top Threats: Tenable's patented Vulnerability Priority Rating
History: History of scan results initiated on the network

﻿<img width="2048" height="1172" alt="image" src="https://github.com/user-attachments/assets/d7bfc322-4d72-44e0-9a30-531269c56ea1" />


4. Analyze the information presented under the tab Hosts and the provided attachment of the mission partner's network map to accurately pinpoint the hosts that have been scanned for vulnerabilities. 


5. Select the tab Vulnerabilities and analyze the information presented for more specific details regarding each vulnerability. 


6. Select the tab VPR Top Threats analyze the information regarding remediation efforts to effectively reduce risk.


This tab reveals severe flaws in the configuration of the critical IT infrastructure within the mission partner's network environment. These flaws may lead to grave damage to the architecture.


7. Select the vulnerability MS17-010: Security Update for Microsoft Windows SMB Server, as highlighted in Figure 26.2-5, below, to display more information regarding the criticality of this vulnerability.


<img width="2048" height="1094" alt="image" src="https://github.com/user-attachments/assets/42be26f5-ec62-4528-abe3-4fef8128a9c5" />

The information indicates that a single host is affected by MS17-010. This vulnerability allows adversaries to remotely execute arbitrary code and gain access to a network by sending specially-crafted packets. The code exploits a software Input Validation vulnerability in Microsoft's Windows OS SMBv1 protocol that allows access to files on a remote server. Adversaries can compromise the entire network through the host and all devices connected to the host, making remediation efforts difficult. This exploit is also known as EternalBlue. Other ransomware such as WannaCry can also take advantage of this exploit. 

-------------------


Prioritize Vulnerabilities With Elastic Stack
In this scenario, the mission partner states that there has been network traffic present within the network regarding the vulnerability MS17-010 from Sep 22, 2022 @ 10:00:00.000 to Sep 22, 2022 @ 13:00:00.000. 

﻿

Prioritize Critical IT Infrastructure Vulnerabilities with Elastic Stack
﻿

Use Elastic Stack to prioritize the mission partner's critical IT infrastructure for the vulnerability.

﻿
﻿

Workflow
﻿

1. Log in to the VM kali-hunt using the provided credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Open a Firefox web browser from the desktop and select the bookmark Security Onion. 

﻿

NOTE: If prompted for credentials, log in with the following, then select the bookmark, again:

Username: trainee@jdmss.lan
Password: CyberTraining1!
﻿

3. Select the hamburger menu at the top left, then select Kibana in the section Tools.

﻿

This displays the Security Onion - Home Dashboard.

﻿

4. Select Alert under Event Category in the pane Security Onion - Navigation, as displayed in Figure 26.2-6, below:


<img width="2048" height="1071" alt="image" src="https://github.com/user-attachments/assets/10a04505-de24-4546-9b47-6a2acc5bd2a3" />


5. In the field highlighted in Figure 26.2-7, below, set the time period from Sep 22, 2022 @ 10:00:00.000 to Sep 22, 2022 @ 13:00:00.000, then select Refresh

<img width="2048" height="1058" alt="image" src="https://github.com/user-attachments/assets/26717b62-3f4a-4cbb-8586-667531f52a84" />


Network data associated with the critical IT infrastructure within the mission partner's network environment has been logged and the severe vulnerabilities can be identified and analyzed. 


Modern instances of SMB use TCP port 445 for direct host-to-host communication in the client-server model. SMB port 139 is used along with Network Basic Input/Output System (NetBIOS) name resolution — requiring NetBIOS ports for resolution — to perform the same operation. In the case of the vulnerability MS17-010, adversaries can leverage SMBv1 and TCP port 445 to propagate malware and perform lateral movements in the network. After the initial SMB handshake, an administrative share on the remote machine can be compromised. 


Forming a Kibana Query Language (KQL) query and using filters can help detect the use of the SMB protocol.


6. To analyze events using port 445, add the following filter then select Refresh:
destination.port: 445 



As displayed in Figure 26.2-8, below, this returns 283 events that pertain to the usage of port 445. By analyzing the returned data, there are rules and highly critical events pertaining to SMB usage within the mission partner's network. 

<img width="2048" height="1379" alt="image" src="https://github.com/user-attachments/assets/22572fe2-a1f7-464a-bd4d-2c29b5ee615c" />


7. To allocate SMB usage along with the exploit MS17-010, apply the following rules to the search:
event.severity_label.keyword: high AND
rule.name.keyword: ET EXPLOIT Possible ETERNALBLUE Probe MS17-010 (MSF style)



Another way to complete step 7 is by selecting + next to the rule under the pane Security Onion - Rule - Name.


8. Scroll down to the pane Security Onion - All Logs and analyze the fields destination.ip and message in the log @ 12:33:11.272.


The results displayed in Figure 26.2-9, below, indicate the SMBv1 on the vulnerable host in the mission partner's network has been exploited

<img width="2048" height="388" alt="image" src="https://github.com/user-attachments/assets/3510e2e0-e43e-4f9d-aed6-d65983621bfd" />


9. Remove the previous filter rule and replace it with the following rule:
rule.name.keyword: ET POLICY Powershell Activity Over SMB - Likely Lateral Movement



Another way to complete step 9 is by selecting + next to the rule under the pane Security Onion - Rule - Name.

<img width="2048" height="338" alt="image" src="https://github.com/user-attachments/assets/ba3e5a4a-67f9-40c1-817d-4758695fe1a4" />


10. Scroll down to the Security Onion - All Logs pane and analyze the field message in the log @ 12:59:40.698.


As displayed in Figure 26.2-11, below, a connection was made to a share other than IPC$. Further analysis of the situation is required to discover whether any data has been compromised. 

<img width="2048" height="280" alt="image" src="https://github.com/user-attachments/assets/90ed70ea-c833-4d64-bf6d-075c8509f884" />

Considering the mission partner's network is vulnerable to SMBv1 attacks, all hosts infected need to be disconnected from the network to be assessed further. Analysts must then clear current MCA and conduct hardening to prevent future risks before moving on to the post-incident activity. The following are possible hardening actions that may apply:
Ensure unnecessary services are disabled.
Ensure the latest patches are installed.
Remediate insecure configurations.
Audit installed software.
Enforce an audit policy.
Enhance security systems and logging.
<img width="1914" height="759" alt="image" src="https://github.com/user-attachments/assets/ad4ff979-7f9f-420f-99fc-6e3238443af4" />
<img width="1864" height="794" alt="image" src="https://github.com/user-attachments/assets/47d157f9-fdc6-4fd7-91c1-64e726fc9c4e" />

<img width="1097" height="528" alt="image" src="https://github.com/user-attachments/assets/334837c4-03a4-4f72-87e1-d360e0dae535" />
<img width="1903" height="765" alt="image" src="https://github.com/user-attachments/assets/b8de632e-4b72-4364-85db-548649606320" />

<img width="1121" height="685" alt="image" src="https://github.com/user-attachments/assets/1da7868d-b77f-436f-b8aa-8c388d65d09a" />
<img width="946" height="293" alt="image" src="https://github.com/user-attachments/assets/f5ee4d6b-1d57-4b26-852e-cca1f1d5c85d" />

<img width="1078" height="672" alt="image" src="https://github.com/user-attachments/assets/736d3f49-1aeb-4fb2-833c-e736a0f4b9e2" />




--------------

### CDAH-M26L3-Responding in an OT Environment ###

Operational Technology
In securing computer networks, most devices in a network are associated with IT. This includes devices for storing, transferring, and securing data. However, other network devices must be considered when securing networks. These devices, known as Industrial Control Systems (ICS), control heavy factory machinery and measurement capabilities. Security considerations for these OT devices differ from IT network devices, as the OT devices keep machines running at all times. 

﻿

Industry Impact
﻿

All industries need OT, and attacks on ICSs have varying impacts, depending on the industry being attacked and the versatility of these systems. Examples of the most highly impacted industries are as follows:


Automobile factories
Chemical processing
Construction
Food production
Manufacturing
Nuclear
Oil/gas
Power/utilities
Transportation
Waste management
Water treatment

Severe repercussions are possible for both IT and OT in the event of a network attack, as Table 26.3-1 shows: 


<img width="1667" height="531" alt="image" src="https://github.com/user-attachments/assets/91e77ad9-1395-4f07-9417-c52c6ccc271d" />


OT systems are used invasively in each industry to have efficient automation of processes and safety. Many of these industries are dangerous to humans but can be managed through the use of mechanical robots controlled with OT. Such robots usually cannot have any productional downtime and communicate with surrounding technology in unique ways. 


Systems


Common systems have devices working in tandem to perform tasks based on the reading of other devices. Systems used in OT networks are as follows: 

ICSs: ICSs may be composed of one device or thousands. ICSs have interweaving instruments meant to measure and react to those measurements to complete daily activities.
Distributed Control Systems (DCS): In a DCS, the OT that is set up has no administrative controls. It runs on a series of control loops that allows the system to manage itself.
Supervisory Control and Data Acquisition (SCADA): SCADA systems provide a level of administration to OT devices. Through a SCADA system, an engineer can manipulate and control variables on such devices as Programmable Logic Controllers (PLC), as necessary.
Devices


OT devices tend to be built with their sole functions in mind, without much regard to their own security. They work in a network to take measurements and readings or perform functions based on these readings. OT devices are divided into the following classifications. 


Programmable Logic Controllers 


PLCs are simple computers built for industry processes for automation. They are designed to withstand the pressures of intense factory environments. PLCs must function in real time, with an ability to provide prompt communications to their surroundings to control the processes as they are being completed. 


Remote Terminal Units 


Remote Terminal Units (RTU) transmit device telemetry and control signals between equipment and SCADA systems.


Digital Protective Relays, Numerical Relays, Intelligent End Devices 


Digital protective relays, numerical relays, and intelligent end devices are advanced power surge protectors and power regulators.


Phasor Measurement Units 


Phasor Measurement Units (PMU) are voltage and amperage management devices, ensuring that the correct amount and power needs are allotted to the relevant device.


Real-Time Operating Systems


A Real-Time Operating System (RTOS) is a device OS designed to not fluctuate during operation. IT OSs may vary significantly in performance of similar tasks, but OT RTOSs must be predictable and are therefore designed to perform the same function in exactly the same manner and same amount of time during every cycle.


Sensor Networks 


Sensor networks are usually monitor-only telemetry units that report information back to a DCS or SCADA system. For example, a network of temperature sensors for refrigeration does not perform any control functions on the refrigeration system but reports back performance, temperature, and other telemetry data.


Human-Machine Interfaces 


A Human-Machine Interface (HMI) is any device, or part of a device, designed to allow people to interact with a machine. An HMI may be a control panel composed of buttons and a simple screen, or it may be a piece of software that sends commands to equipment over a network.


Operational Technology Network Example


In Figure 26.3-1, the SCADA server, which allows control of the other devices, is managed through the HMI. The SCADA server manages the PLCs’ tasks on the industrial equipment inside the power plant, based on the readings received from the RTU, which receives data from the temperature sensor.



<img width="1667" height="1770" alt="image" src="https://github.com/user-attachments/assets/d26a448c-7f8d-4813-b648-bd96ed883db5" />

<img width="1093" height="643" alt="image" src="https://github.com/user-attachments/assets/afdd674b-0f95-4816-9f1d-b8c768e40269" />
<img width="960" height="593" alt="image" src="https://github.com/user-attachments/assets/c6933dfb-0cba-4727-98ed-94b3440d4057" />
<img width="1053" height="593" alt="image" src="https://github.com/user-attachments/assets/777fa9fc-8225-4d0c-8756-b284d3b2ae84" />


-----------------

Incident Response in Operational Technology
Differences between OT and IT
﻿

Due to the nature of OT ICSs, performing IR in an OT environment requires a different approach from the IT environment. To create the best IR program for OT devices, the differences between OT and IT devices must be understood. Devices perform different roles in the network, and the risks and vulnerabilities they display are vastly different as well.

﻿

Current industrial processes are impossible without networks containing both OT and IT devices. Administrators must interact with both to complete day-to-day functions successfully. The following offers guidance on the differences between IT and OT networks.

﻿

Primary Differences
﻿

OT/ICS assets are often inaccurately compared to IT assets. During an incident, IT and OT/ICS systems have different missions, objectives, and impacts. The primary differences between IT and OT/ICS systems are in six areas, as shown in Figure 26.3-2: security IR, safety, skill sets, system designs, support, and security controls.

﻿

NOTE: Figure 26.3-2 is adapted from a SANS Institute resource, identified in Additional Resources below.


<img width="1667" height="1092" alt="image" src="https://github.com/user-attachments/assets/8fc0acd6-199e-4c06-941f-aa3dd4d20255" />

Figure 26.3-2
Security IR: IT and OT/ICS systems have different devices, missions, objectives, and impacts during an incident. Adversaries targeting ICS must use different attack Tactics, Techniques, and Procedures (TTP) for access, execution, collection, and persistence to degrade safety, manipulate control, and damage physical engineering assets or property. 
Safety: The main goals for OT/ICS systems are not Confidentiality, Integrity, and Availability (CIA), as they are for IT. Rather, the OT/ICS primary goal is safety of personnel, followed by integrity to trust operational commands, availability, and then confidentiality.  
Skill Sets: IT and OT/ICS security teams differ in their unique security skill sets. OT/ICS teams focus on nontraditional systems, protocols, and engineering systems. 
System Designs: OT/ICS systems contain nontraditional computer and legacy systems with industrial and proprietary protocols. 
Support: OT/ICS systems rely on external vendor support. 
Security Controls: Security controls are used to perform different actions, depending on whether they are used within an IT or OT/ICS environment. 


---------------

IT vs. OT Physical Environments
The physical environments of IT and OT networks are different. IT networks are often accessed from an office, whereas OT networks are decentralized and may be located in remote areas, often next to the related OT equipment of the network. Table 26.3-2 provides a list of IT and OT device physical environments and characteristics:

<img width="1667" height="1475" alt="image" src="https://github.com/user-attachments/assets/6f51230c-f682-496a-98fe-d1be00c3ca32" />

-------------------------

Industrial Control System Roles
ICS roles and responsibilities have similarities with IT systems. The subtle differences that are built in warrant consideration during IR.

﻿

Network/System Administrators
﻿

System administrators manage the IT aspect of the ICS systems, interconnecting Transmission Control Protocol/Internet Protocol (TCP/IP) devices, configuring computer systems, and monitoring security. The main focus of IT administrators in an OT environment is to secure the IT equipment that can potentially affect OT operations. 

﻿

Administrators, analysts, and other IT personnel are tasked with managing the servers and workstations that other members of a given organization use daily. Some SCADA systems may be running on Windows or Linux machines that IT manages, but OT equipment rarely falls under general IT purview.

﻿

Operators/Engineers/Technicians
﻿

Operators use the OT systems to manage, monitor, and program the physical processes. Operators include any personnel who require OT equipment to perform their relevant functions. A nurse using vital signs monitors and a factory worker cutting steel beams are both considered operators in an OT environment. Engineers and technicians vary across a wide range of disciplines, and OT software engineers may have some overlap with IT administration and security, but technicians and equipment engineers only manage or repair OT-related equipment.

﻿

Security personnel and analysts likely interact with SCADA- and DCS-related systems rather than controllers and device-level components. Every equipment vendor has different tools for managing updates and administration for devices, and security personnel are tasked with learning all the vendor-specific information needed to secure OT systems.


-----------------

OT/ICS Vulnerability Management
Most OT/ICS components and protocols are sensitive to unexpected or improperly formatted control messages. Use of traditional IT tools, such as vulnerability scanners or port mappers, can cause system instability or even permanent damage. Many OT/ICS devices have only their manufacturer management network port open for communication and are designed only to receive network traffic from their proprietary software. For the sake of availability and operational speed, many standard IT-related communication functions are removed from device controllers, and simple handshakes and remote session requests cause system failure. Because of this, most modern controllers reject all traffic from standard IT devices to maintain stability.

﻿

Some ICS functions, such as HMIs or data historians, can be hosted on traditional enterprise Operating Systems (OS) like Microsoft Windows or Linux. Telemetry data–generating machines like an HMI do not send many instructions to device controllers and, instead, are simply receiving forwarded telemetry data that is then sent upstream to a SCADA system, for example. Traditional IT monitoring and investigation tools, such as PowerShell, Sysinternals, or IR scripts, may not be supported on these devices, however. Such devices rely on passive information-gathering techniques rather than active tools in field networks.


----------------


Incident Response Differences
OT/ICS includes the steps of IT IR: Preparation; Detection and Analysis; Containment, Eradication, and Recovery; and Post-Incident Activity. However, OT/ICS includes additional steps, and each step must be adapted for the safety and reliability of operations that prioritize personnel and the protection of physical assets within the organization. 

﻿

Preparation
Risks: OT risks on the incident-rating scale involve more danger than IT networks, as the machinery being controlled by OT devices can be dangerous.
Roles and responsibilities: Who is responsible for OT devices during an IR?
Stakeholders: Does everyone understand the impact OT devices have on a network?
Communication: If separate IR teams exist, how do they interact?
Attack vectors: What are the types of attacks that can be performed on OT devices?
Detection and Analysis
Detection by user observation: Such detection includes any member of the organization, including operators, process engineers, or system administrators observing abnormal system or component behavior.
Detection by automation: Such detection includes abnormal system or component behavior detection through applications or routines, such as network monitors, network traffic analysis applications, IDSs and antivirus programs detecting and flagging malware, intrusion attempts, policy violations, exploits, and component failure. 
Analysis: IR team members analyze captured events from user observations or IR tools. Once an attack is properly identified, the incident should be categorized and the response prioritized based on the potential damage to the ICS. 
Containment, Eradication, and Recovery
Containment: Containment varies, depending on the type of malware, importance of the affected system, and the acceptable level of risk. It also serves two purposes: to stop the spread of malware to other parts of the ICS and to prevent damage to the ICS. 
Eradication: Any malware left on the system should be eradicated. The process of removing malware can be time consuming, depending on the type of malware, severity of the infection, and containment method used. Such eradication tools as spyware detection and removal utilities and patch management software can be used but may remove or alter legitimate system or data files. Most antivirus software focuses on IT systems and does not detect malware on more specialized control systems. 
Recovery: Although some recovery commonalities exist between IT and ICS environments, such as removal of malware, restoring backup data to databases, systematically removing temporary containment actions, and restarting all operation systems and applications, additional complexities relate to ICS environments. These complexities relate to the manner in which systems must be managed, because many of the services provided by the facility cannot be shut down during IR. Other approaches must be taken, such as switching the control functions to fail-over systems, moving to temporary backup equipment with limited capabilities, or isolating system components from network access. Processes continue to operate but with reduced functionality.  
Post-Incident Activity
Lessons learned: An attempt is made to analyze the incident, the response, and the impact to discover and document what could have been done differently to improve upon the response. 
Recurrence prevention: Such prevention includes applying what was learned in remediating discovered weaknesses in the cybersecurity program, including preventing similar incidents. 
Forensics and legal issues: This includes capturing and protecting data as evidence for potential legal action. 

---------------

Securing IT and OT Devices
Security controls are used to perform different actions, depending on whether they are used within an IT or OT network, as shown in Table 26.3-3:

﻿<img width="1284" height="2048" alt="image" src="https://github.com/user-attachments/assets/6f5d508d-a018-4d87-aa62-eec6b0507aef" />

Network Intrusion Detection and Prevention 


All network IDSs/IPSs deployed within a network environment should be able to conduct Deep Packet Inspection (DPI) and interpret ICS protocols and commands. However, false positives can occur when conducting network inspections. Thus, an IDS alerting suspect network traffic on a control network is more suitable than an IPS because IPS solutions may block or drop network traffic that could end up being legitimate control commands, which wrongly disrupts the control system. 


Vulnerability Scanning


Automated vulnerability scanning in IT is a common practice and does not interfere with processes. In OT, vulnerability scanning can have undesirable effects on aged firmware versions or legacy devices not designed to handle abnormal network traffic patterns. This disparity requires a cautious approach to vulnerability scanning in ICS to minimize the risk of inadvertently taking down critical systems. Alternatively, vulnerability scanning in an ICS can be conducted effectively by comparing asset inventories, configuration files, and firmware versions against threat intelligence and vulnerability advisories.  


Encryption


Confidentiality on the network’s OT side is less of a requirement than on the network’s IT side. Encrypting insecure channels can protect both IT and OT networks. Adhere to endpoint processing power, network latency, and bandwidth consumption, especially in networks that consist of legacy devices. The risk of adversaries eavesdropping or sniffing personal data inside the OT network is not the same as on the IT side of the network, and Network Security Monitoring (NSM) defense capabilities may be severely limited if the control network is encrypted. 


Endpoint Protection


Most IT environments consist of signature-based endpoint protection or heuristic engines to identify threats. Signature-based endpoint protection tools are not ideal within OT environments, as they are difficult to update. These tools can cause false positives and disrupt industrial processes, causing unsafe conditions. To avoid such issues, allowlisting features are effective and do not require signature or constant updates. 


Firewalls


OT devices require the defensive capabilities of firewalls as much as IT devices do. They differ in the necessity of what traffic is being prevented from accessing these systems. In a regular IT network, these firewalls segment areas of the network that have no need to communicate with each other. They are also commonly used to block specific ports and protocols from being used. In an OT environment, they should completely isolate the ICS network for the rest of the network. The internet should have no connectivity; this is also true for any workstation or server in the domain, with the exception of any HMI device specifically inserted to administer these devices.


Patching


In IT, device patching is a routine occurrence that happens on a common schedule or whenever a vulnerability is discovered. IT networks can administer reboots to individual boxes or whole subnets of the network without the rest of the network being shut down. OT devices, on the other hand, control the industrial machinery, and if they are rebooted or shut down for updates, the industrial machines cannot function. Patching for these devices must be scheduled in advance at a time during which the factory is not in operation. Patching is not possible with some legacy ICS devices.


Protocols


Some traditional protocols are used within both IT and OT environments. However, control system environments go well beyond common protocols and may include specific industrial and several proprietary protocols, as Table 26.3-4 shows:


<img width="1600" height="1358" alt="image" src="https://github.com/user-attachments/assets/0c58fe8c-7c7f-4455-b4bb-9ac66a6055cd" />


--------------------

IT/OT Device Convergence
IT and OT convergence may be broken down into two elements: technology and resources (or teams). OT and IT devices leverage traditional OSs and infrastructure to automate and improve control system processes. The OT devices support the control system mission and should be properly managed and protected as OT assets. Controlling ICS networks is becoming easier with the possibility of remote administration and is a more efficient way to manage these systems. Administrators of OT devices are no longer always specialized engineers in this field. Instead, they may be any IT personnel with proper training in such ICS-specific areas as the ICS mission, safety, the engineering process, protocols, and active defense strategies. Understanding how these devices must be handled and secured in different scenarios is different from traditional IT security. 



--------------

IR in OT and IT Architecture | Part 1
A Cyber Defense Analyst (CDA) has been tasked by a mission partner to assist in analyzing suspicious network traffic affecting the IT side of the network that is potentially causing disruption in the functionality of OT processes.

﻿

The OT side of the network environment consists of a number of virtualized networks in addition to a functioning simulation of a Feed Water Treatment System (FWTS). A virtualized PLC leverages the Modbus protocol to monitor process measurements and accept commands from the HMIs within the DCS network.

﻿

Use Elastic Stack to analyze the suspicious activity and logs to understand the differences in behavior of the IT and OT devices in the mission partner’s network environment. A network map of the mission partner's network environment is attached.

  

Workflow 
﻿

1. Open the Virtual Machine (VM) win-hunt. The login credentials are as follows:


Username: trainee
Password: CyberTraining1!
﻿


2. Open the Chrome web browser, select the Security Onion bookmark, and log in using the following credentials:

Username: trainee@jdmss.lan
Password: CyberTraining1!
﻿


3. Select the hamburger menu icon in the top left corner, and select Kibana in the Tools section:



<img width="2012" height="1270" alt="image" src="https://github.com/user-attachments/assets/9f253ac3-db81-4c79-a5e8-d61c091ae52a" />

The Security Onion - Home dashboard appears.


4. Select the hamburger menu icon again, and select Discover in the Analytics section

<img width="2014" height="1112" alt="image" src="https://github.com/user-attachments/assets/3579f139-74f1-4241-b84c-0293cae9cad8" />

5. Set the time period of interest from Sep 29, 2022 @ 10:00:00.000 to Sep 29, 2022 @ 13:00:00.000, and select Update. 


Compare IT and OT captured network traffic logs from the mission partner’s network. A functioning IT workstation is located in the Business Processing Department of the network. On the OT side of the network, the PLC leverages the Modbus protocol to monitor process measurements from the FWTS and receives commands from the HMI. Messages containing the Modbus protocol are embedded into the frame or packet structure used on the OT network. 


6. Use the following Kibana Query Language (KQL) query to locate the network traffic associated with the host in the Business Processing Department, and select Update:


destination.ip: 172.16.3.2

<img width="2036" height="298" alt="image" src="https://github.com/user-attachments/assets/4c095151-30cf-473b-902f-317fb6d93545" />

7. Scroll down, and analyze the log captured on Sep 29, 2022 @ 12:28:26.976:

<img width="2036" height="1360" alt="image" src="https://github.com/user-attachments/assets/12afcbe6-127b-49b8-a90c-a386cd4cf687" />

IT includes any use of computers, storage, networking devices, infrastructure such as Domain Controllers (DC), and processes to create, store, secure, and exchange all forms of data. 


Notice in the message field that the workstation is communicating with the DC to edit policies over the Server Message Block (SMB) protocol. These particular actions do not occur with OT devices. 


8. Remove the previously used KQL query, and use the new KQL query to search for the IP address of the PLC. Select Update: 


source.ip: 172.16.80.10




9. Add the following filter to analyze Modbus protocol traffic, and select Save:


event.dataset.keyword: modbus

<img width="2036" height="1368" alt="image" src="https://github.com/user-attachments/assets/157a2d05-ac0e-45fc-9e5d-dfe7b148ec62" />



NOTE: Refresh data if no data shows after adding filter.


10. Scroll down and analyze the log captured on Sep 29, 2022 @ 12:59:59:980: 

<img width="2036" height="1366" alt="image" src="https://github.com/user-attachments/assets/1cb20932-2158-470a-a54f-b32f64d95cdc" />

Such OT devices as PLCs use the Modbus protocol over port 502. The messaging structure of Modbus uses client–server communication between devices, which transmits functions such as READ and WRITE input registers. These registers tell the device what function to perform. 



-----------

IR in OT and IT Architecture | Part 2
The mission partner reports that an employee has come forward stating that they downloaded an unknown executable file from an email they thought was from their manager. Since the download occurred, the host within the Business Processing Department has been seen making unwarranted interactions with the PLC. The FWTS has also produced erratic behavior.

﻿

In the following workflow, use Elastic Stack to analyze the captured network traffic between the host in the Business Processing Department and the PLC. Use the findings to assess and compare IR actions for the IT and OT architecture. A network map of the mission partner’s network environment is attached. 

﻿

Workflow 
 ﻿

1. Remove the Modbus filter and KQL query that was set in the previous task, and add a new query, to include the following:

﻿

source.ip: 172.16.3.2 and destination.ip: 172.16.80.10

﻿

Forty-one captured log hits should result between the two IP addresses:


<img width="2036" height="772" alt="image" src="https://github.com/user-attachments/assets/3edc5037-bd85-466c-a567-5485008bede5" />




2. Analyze the log captured on Sep 29, 2022 @ 12:41:44.556. Notice the port and protocol used as a line of communication between the two devices. 


An IT workstation should not be making these types of connections with a PLC device. This traffic can be deemed malicious, as this is lateral movement toward the control environment. The situation warrants further investigation, as processes within the organization may be disrupted. 


The workstation of the victim employee is possibly being used as a pivot point to access the OT network and disrupt services of the organization. Containment of the IT workstation is necessary to observe and characterize adversary behavior and TTPs to enable follow-on operations. However, the PLC device cannot be disabled, as this controls the FWTS and will disrupt the organization’s processes. The traffic warrants further investigation using Zeek logs to determine if a false positive has been captured, as processes within the organization can be disrupted.


3. Select the hamburger menu icon, and select Dashboard under Analytics. 



The Security Onion - Home dashboard should now be present. 


NOTE: If the Security Onion - Home dashboard does not appear, enter Home in the search bar, and select the Security Onion - Home dashboard.


4. Select Network under Event Category: 



<img width="2048" height="799" alt="image" src="https://github.com/user-attachments/assets/f90a91dd-a1ca-4aa3-825b-b3ebcd08ac0c" />



5. Edit the KQL query search bar to include the IP address of the PLC in the query. Select Refresh:


event.category: network and source.ip: 172.16.80.10




6. Analyze the Security Onion - Destination IP pane:



<img width="263" height="380" alt="image" src="https://github.com/user-attachments/assets/d67479c6-a395-4e10-9ca6-7be50aa87ac3" />


Not only are unwarranted connections being made to the PLC from the Business Processing Department workstation, but a connection is also being made to an IP address outside the scope of the network environment. As a false positive can be ruled out, this malicious IP address may well be the perpetrator of these events. The IR process can be further elevated. 


As mentioned earlier in the lesson, the steps of IT IR still adhere to the OT/ICS IR process. 


If malware is not detected on the OT device, containment of the PLC device requires removing access to the device from all sectors of the network. Containment includes the following:
Block the intruder.
Restore the equipment, if affected.
Apply prevention methods, such as patch management. 
If malware is detected on the OT device, it is best to prevent continued damage to the control systems. Containment methods include the following:
Use automated technologies such as virus removal programs to eradicate the virus and prevent spreading to other systems and restore system functions.
Halt services while the incident is handled.
Block certain network connectivity by using filtering processes. 
Regarding OT recovery and restoration in the IR process, although commonalities with IT exist (such as removal of malware, restoring backup data to databases, systematically removing temporary containment actions, and restarting all operational systems and applications), other approaches must be taken because many services cannot be shut down. Such approaches include the following: 
Switch the control functions to fail-over systems.
Move to backup equipment that is temporary or has limited capabilities.
Isolate system components from network access.
The final stage of recovery is not to just restore the system to where it was but, rather, to make it more secure. The system should have the same operational capabilities but should also protect against the exploit that caused the incident in the first place. 


Answer the following questions.
<img width="1125" height="646" alt="image" src="https://github.com/user-attachments/assets/18971446-7d8b-4924-b01f-f6573d2fc1bc" />
<img width="1070" height="641" alt="image" src="https://github.com/user-attachments/assets/cecb616a-5d23-41e4-ae2c-7f3c1c975e77" />
<img width="1124" height="662" alt="image" src="https://github.com/user-attachments/assets/017f6e47-a056-4e4d-bc08-559d9543ba4c" />
