### CDAH-M29L1-ICS Architecture ###


Operational Technology vs. Information Technology
OT and ICS are devices and controllers that manage physical industrial equipment and operations. OT devices are hardware and software systems that interface directly with a piece of industrial hardware. OT/ICS controllers may be found on any physical equipment, such as equipment cranes, hospital patient health monitors, and refrigeration sensors. Any microcomputer attached to a physical device and designed specifically to make that device function is an OT device.

﻿

OT/ICS devices are divided into categories based on the kinds of data and equipment they control and how the equipment is controlled. The most common examples are as follows:

Supervisory Control and Data Acquisition (SCADA): SCADA systems are comprehensive system solutions that allow operators to see an entire system’s process within an industrial context; a SCADA suite often includes direct system management tools. An example is a software suite that displays a power plant’s relevant operational data for all the machines that make the power plant function rather than for individual pieces of equipment.
Distributed Control System (DCS): Similar to SCADA, DCSs create a hierarchical structure of management based on a worker’s role. DCS management levels range from level 0 to level 4, where 0 is a direct machine operation console and 4 might be a plant manager's station. Usually, however, DCS setups are entirely onsite, with no remote administration. For example, a steel mill might use a DCS-based setup to manage factory operations and even report its level 4 data to its parent company’s SCADA setup.
Programmable Logic Controller (PLC): PLCs are the devices directly connected to the equipment being operated. PLCs usually have some kind of networking built in so that the device can be managed by DCS or SCADA systems. 
Differences between IT and OT Asset Management and Security
﻿

IT and OT devices are managed, maintained, and secured differently due to the nature of the organizational needs they fulfill. IT devices like servers and user workstations are designed to fulfill a large number of functions. IT Operating Systems (OS) like Windows contain a multitude of tools so that a user’s needs may be met across a wide range of business disciplines. OT devices, on the other hand, often contain only the system code and function required to operate the specific task they are required to perform. OT devices often need nearly 100% uptime; a power plant’s generators, for example, cannot simply be disabled for updates and routine patches. OT equipment usually entails much greater safety concerns than IT devices. If a Dynamic Host Configuration Protocol (DHCP) server goes down, users may need to stop work briefly, but if a hospital heart monitor stops working, a patient’s physical health may be in jeopardy.

﻿

Another difference between IT and OT devices is their relative lifecycles. Whereas new IT equipment is replaced, upgraded, and refreshed every few years, OT/ICS equipment is often in place for 1 or 2 decades before being removed due to equipment failure or to a forced equipment change for a new organizational requirement.

﻿

OT security has several challenges that IT security lacks. OT devices are often not directly manageable with IT patching solutions and instead may require custom management software, if a fix is available at all. Direct administration is also not an option for most OT devices, as controllers do not contain full OSs and can be accessed only through a physical control panel or through proprietary management software provided by the manufacturer.



-----------------


Industrial Control System Components
OT/ICS equipment consists of several components that work together to create a fully operational environment:

PLCs: PLCs are devices attached directly to physical equipment that governs the operation of that equipment.
Remote Terminal Units (RTU): RTUs transmit device telemetry and control signals between equipment and SCADA systems.
Digital Protective Relays, Numerical Relays, and Intelligent End Devices: Digital protective relays, numerical relays, and intelligent end devices are advanced power surge protectors and power regulators.
Phasor Measurement Units (PMU): PMUs are voltage and amperage management devices, ensuring that the correct amount and kind of power needs are being given to a relevant device.
Real-Time Operating Systems (RTOS): An RTOS is a device OS that is designed to not fluctuate during operation. IT OSs can vary significantly in performance of similar tasks, but OT RTOSs must be predictable and are therefore designed to perform the same function in exactly the same manner, and in exactly the same amount of time, every time.
Sensor Networks: Sensor networks are usually monitor-only telemetry units that report back information to a DCS or SCADA system. A network of temperature sensors for refrigeration does not perform any control functions on the refrigeration system but does report back performance, temperature, and other telemetry data.
Human-Machine Interfaces (HMI): An HMI is any device, or part of a device, designed to allow people to interact with a machine. An HMI may be a control panel composed of buttons and a simple screen, or it may be a piece of software that sends commands to equipment over a network.
﻿Figure 29.1-1 provides an OT network example. The SCADA server, which allows control of the other devices, is managed through the HMI. The SCADA server manages the PLCs’ tasks on the industrial equipment inside the power plant, based on the readings received from the RTU, which receives data from the temperature sensor.

<img width="1667" height="1770" alt="image" src="https://github.com/user-attachments/assets/93258b4a-fbf2-4d44-b01a-4118e0f3b9e5" />


------------------


Industrial Control System Roles
Administration and security within an OT/ICS environment are often divided into roles to set responsibilities and tasks for the correct personnel.

﻿

Network/System Administrators 
﻿

System administrators manage the IT aspect of the ICS systems, interconnecting Transmission Control Protocol/Internet Protocol (TCP/IP) devices, configuring computer systems, and monitoring security. The main focus of IT administrators in an OT environment is to secure the IT equipment that can potentially affect OT operations. IT administrators also manage and secure all after-business critical systems just like any other IT environment.

﻿

Administrators, analysts, and other IT personnel are tasked with managing the servers and workstations that other members of a given organization use daily. Some SCADA systems may be running on Windows or Linux machines that IT manages, but OT equipment rarely falls under general IT purview.

﻿

Operators/Engineers/Technicians 
﻿

Operators use the OT systems to manage, monitor, and program the physical processes. Operators include any personnel who require OT equipment to perform their relevant functions. A nurse using vital signs monitors and a factory worker cutting steel beams are both considered operators in an OT environment. Engineers and technicians vary across a wide range of disciplines, and OT software engineers may have some overlap with IT administration and security, but technicians and equipment engineers manage or repair only OT-related equipment.

﻿

Security personnel and analysts likely interact with SCADA- and DCS-related systems rather than controllers and device-level components. Every equipment vendor has different tools for managing updates and administration for devices, and security personnel are tasked with learning all the vendor-specific information needed to secure OT systems.


---------------

Security Tool Use in Industrial Control System Environments
OT/ICS Vulnerability Management
﻿

Most OT/ICS components and protocols are sensitive to unexpected or improperly formatted control messages. Use of traditional IT tools, such as vulnerability scanners or port mappers, can cause system instability or even permanent damage. Many OT/ICS devices have only their manufacturer management network port open for communication and are only designed to receive network traffic from their proprietary software. For the sake of availability and operational speed, many standard IT-related communication functions are removed from device controllers, and simple handshakes and remote session requests cause system failure. Because of this, most modern controllers reject all traffic from standard IT devices to maintain stability.

﻿

Some ICS functions, such as HMIs or data historians, can be hosted on traditional enterprise OSs like Microsoft Windows or Linux. Telemetry data–generating machines like an HMI do not send many instructions to device controllers and, instead, simply receive forwarded telemetry data, which is then sent upstream to a SCADA system, for example. Traditional IT monitoring and investigation tools, such as PowerShell, Sysinternals, or IR scripts, may not be supported on these devices, however. Such devices rely on passive information-gathering techniques rather than active tools in field networks.

﻿

-----------

Scan ICS Networks
The following exercises use a simulated Feed Water Treatment System (FWTS) OT network that is part of the vCity Power Plant. The system owner provided the attached network diagram. 

﻿

Complete the steps in the following workflow to identify assets on the OT network and demonstrate potential negative impacts of active scanning in an OT network. 

﻿

Workflow
﻿

1. Open a console session to the Virtual Machine (VM) hmi-1.

﻿

The HMI, illustrated in Figure 29.1-2, is a critical device that allows plant operators to monitor and control processes associated with an FWTS:

﻿
<img width="816" height="614" alt="image" src="https://github.com/user-attachments/assets/31583cd2-e3f5-4f04-8ad0-09f986251680" />


2. Open the VM win-hunt. The login credentials are as follows:

Username: trainee
Password: CyberTraining1!



3. Open Zenmap by selecting the Nmap - Zenmap GUI desktop shortcut.


4. Select the drop-down arrow for the Target field, and select the pre-populated address ranges. These address ranges were selected based on the network diagram provided by the system owner. 



<img width="675" height="202" alt="image" src="https://github.com/user-attachments/assets/f8925620-70d7-435c-bc78-ebed12af1e21" />


The Command field is automatically updated with the selected address ranges. This scan profile performs a full TCP connect scan against a small subset of ports that may be found in an ICS network. The command also performs a traceroute to help visualize the network path from the Zenmap scanning host to the target networks. A Cyber Defense Analyst (CDA) typically performs a more complete port scan, but the number of ports in this exercise is reduced to save time.


<img width="677" height="222" alt="image" src="https://github.com/user-attachments/assets/cb53df13-4d76-436c-b6c2-5fb97b8b02f8" />

5. Select Scan

<img width="674" height="204" alt="image" src="https://github.com/user-attachments/assets/f71cbc51-d459-46e1-b7ea-ecdd94ea2b83" />

Once the scan is complete, an Nmap done message appears at the bottom of the Nmap Output display

<img width="671" height="711" alt="image" src="https://github.com/user-attachments/assets/013dd609-37ab-4c71-a450-631b78a371ce" />

6. Select the Topology tab for a high-level visualization of node distribution based on the traceroute feature of Nmap

<img width="674" height="714" alt="image" src="https://github.com/user-attachments/assets/babdfc2a-bf59-4c48-b714-efa74ed343e9" />

The Nmap scan detected most of the hosts in the scanned networks. However, the scanning activity had a negative impact on some assets in the network. 


7. Close the Zenmap console by selecting the X in the upper right corner and selecting Close anyway when prompted. 


8. Return to the VM hmi-1 console session.


The HMI display is no longer visible. The HMI software did not know how to interpret the received data associated with the scan, causing a failure condition. Thus, operators cannot use this terminal to monitor and control the FWTS until the failure is corrected. This is an example of potential impacts that active interactions with ICS components can have. 


Keep the VMs hmi-1 and win-hunt open, as they are used in the next workflow

--------------

Passive Enumeration of Industrial Control System Networks
The following exercise demonstrates how the tool GRASSMARLIN can be used to identify assets in an ICS network through passive detection. GRASSMARLIN is an open-source project developed by the National Security Agency (NSA) that can passively map and visually display an ICS/SCADA network topology while safely conducting device discovery, accounting, and reporting on these critical systems. GRASSMARLIN is capable of extracting this data from live network capture, ingesting a packet capture, parsing Zeek logs, or consuming Cisco® router/switch configuration files and Address Resolution Protocol/Media Access Control (ARP/MAC) caches. The exercise uses a GRASSMARLIN session that was created using offline packet capture from the vCity Power Plant FWTS OT network. 

﻿

NOTE: The VM win-hunt should remain open from the prior workflow. If it has been closed, log in again using the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

Workflow
﻿

1. Open GRASSMARLIN by selecting the GrassMarlin shortcut on the desktop.

﻿

2. Select File  > Open Session:

<img width="318" height="288" alt="image" src="https://github.com/user-attachments/assets/f6525dc3-99d4-45db-9f7e-4b083465fba2" />

3. Select Documents > OT Network Map.gm3, and select Open:


<img width="845" height="483" alt="image" src="https://github.com/user-attachments/assets/689bee27-39b0-49be-8e7f-43f0877a1dca" />

The saved session may require up to 2 minutes to load. The session data was created by ingesting approximately 1.3 gigabytes (GB) of network traffic that was captured by the Network Analyst team monitoring the OT network. Parsing the 1.3 GB of packet capture by GRASSMARLIN required about 15 minutes, which is why the session data was preloaded for the exercise. 


GRASSMARLIN can analyze the captured network traffic to identify network assets as well as define communication flows between these assets. GRASSMARLIN also ships with profiles that can be used to fingerprint the observed device types and protocols.


Once the session loads, the Logical Graph tab is populated with the identified devices, as depicted in Figure 29.1-10. GRASSMARLIN was able to use device fingerprinting to observe Modbus traffic and properly label ICS devices with a power line icon. By default, the detected assets are separated into subnets based on /24 subnet masks, which does not accurately match the network layout. GRASSMARLIN provides the ability to specify custom subnets to enhance the visualization.

<img width="645" height="730" alt="image" src="https://github.com/user-attachments/assets/b98fb22d-71cc-4e8f-9a8e-c9d7d68f35ed" />

4. From the toolbar, select Packet Capture > Manage Networks

<img width="430" height="247" alt="image" src="https://github.com/user-attachments/assets/64b0bba9-291f-4a0b-84ba-d131fd1366d8" />

5. Remove the existing network definitions by selecting the Classless Inter-Domain Routing (CIDR) blocks and selecting the Delete key on the keyboard:

<img width="450" height="134" alt="image" src="https://github.com/user-attachments/assets/07037c13-5854-45c4-969c-7d486f86c51d" />

6. In the Add CIDR field, enter the first CIDR block of 172.16.80.0/29, and select the Add CIDR button

<img width="447" height="296" alt="image" src="https://github.com/user-attachments/assets/e77e6c54-2b12-4593-a2a6-92506ed00a04" />

7. Repeat the previous step to add the following CIDR blocks:
172.16.80.8/29
172.16.80.16/28
172.16.79.32/29

8. Select Finish to complete the process

<img width="446" height="292" alt="image" src="https://github.com/user-attachments/assets/ddb2903d-3bc3-4e1b-b072-d04d481aeedd" />
GRASSMARLIN has updated the Logical Graph to properly identify devices in their appropriate subnets:

<img width="726" height="784" alt="image" src="https://github.com/user-attachments/assets/25170195-2334-46e4-9446-d051ceb47168" />


GRASSMARLIN can also provide information about the type of ICS components that were discovered.
 
9. In the left pane, select the drop-down arrow to the left of the 172.16.80.0/29 subnet. Right-click 172.16.80.2, and select View Details for 172.16.80.2

<img width="508" height="400" alt="image" src="https://github.com/user-attachments/assets/e77adde5-0e7a-47fe-99fc-1d890c4e27eb" />

10. Resize the Node Details window that appears so that the device attributes are visible

<img width="289" height="488" alt="image" src="https://github.com/user-attachments/assets/3465882c-a07d-4fb6-8f8d-4c8a5211d71c" />


GRASSMARLIN has provided several pieces of information based on its fingerprinting capability. In addition to possible product and OS matches, it provides valuable insight into this device’s functional role in the OT network. In this case, 172.16.80.2 has been identified as a Master Terminal Unit (MTU), which is synonymous with an HMI.

<img width="422" height="727" alt="image" src="https://github.com/user-attachments/assets/7c0479b7-8462-4745-a915-08ceb5a3bc29" />


11. Close the Node Details window.


12. Select the drop-down arrow to the left of the 172.16.80.8/29 subnet. Right-click 172.16.80.10, and select View Details for 172.16.80.10


<img width="434" height="432" alt="image" src="https://github.com/user-attachments/assets/cb3300c3-35fd-4fef-9638-e9b033bd9931" />


13. After resizing the window, view the device attributes. In this case, the device category has been properly identified as a PLC:


<img width="441" height="794" alt="image" src="https://github.com/user-attachments/assets/69601160-d654-4525-8175-8fb1080adf49" />


---------------

### CDAH-M29L2-ICS Protocols and Implementations ###

Industrial Control System Protocols
To understand how ICS networks and components communicate, familiarity with the underlying protocols in use is necessary. Protocols implemented in ICS networks are designed to communicate with specialized hardware to complete particular tasks, such as reading sensor values or sending control instructions to an end device. Additionally, some protocols have unique requirements, depending on their applications, such as an emphasis on reliable transport, efficiency due to low-bandwidth communications streams, and extremely low latency to support real-time operations. 

﻿

Like some Information Technology (IT) protocols, ICS protocols can be proprietary or open standard. Proprietary protocols are maintained by the vendors that developed them. The use of these protocols is restricted by licensing requirements and, in general, interoperate only with other devices produced by the vendor. Additionally, the technical information behind the development of the protocols is retained by the vendor and not shared publicly. Open-standard protocols, on the other hand, are free to use by anyone. They are usually designed and developed by organizations like the Institute of Electrical and Electronics Engineers/Internet Engineering Task Force (IEEE/IETF) or as a joint effort by many organizations.


----------------

Common Industrial Control System Protocols
Dozens of communications protocols currently exist in ICSs throughout the world. Some protocols are extremely specialized and used in only certain applications, whereas others have seen widespread adoption throughout the industry. Brief descriptions of some of today’s most common ICS communications protocols follow.

﻿

Modbus
﻿

Modbus is a data communications protocol originally published by Modicon in 1979 and later adopted as one of the first open-standard ICS protocols. Modbus is one of the most commonly used communications protocols in ICS networks. 

﻿

Modbus is a serial protocol that communicates over Recommended Standard 232 (RS232) or RS485 serial connections. A variant known as Modbus/TCP (Transmission Control Protocol) exists that can communicate over Ethernet networks using TCP port 502 by default. 

﻿

Modbus employs a client–server (originally documented as master/slave) architecture for communications. The client initiates communication with the servers to poll for information or send commands to the end device. The Modbus protocol allows a maximum of 247 Modbus devices per network segment. Figure 29.2-1 provides an illustration of the Modbus process:

﻿


<img width="2500" height="1114" alt="image" src="https://github.com/user-attachments/assets/b1fca3b0-037a-4a8f-9f26-885c9d10c01f" />


PROFIBUS/PROFINET


PROFIBUS is an open-standard communications protocol used widely in factory and process automation systems. PROFIBUS is a serial protocol that communicates over RS232 or RS485 serial connections. 


PROFINET is an updated version of PROFIBUS that communicates over industrial Ethernet networks. 


DNP3


Distributed Network Protocol 3 (DNP3) is used almost exclusively by electric, gas, and water utilities for remote communications between Supervisory Control and Data Acquisition (SCADA) equipment and control centers. This protocol operates over RS232 and RS485 serial connections but can also be encapsulated in Transmission Control Protocol/Internet Protocol (TCP/IP) or transmitted via radio or modem for long-distance communications. 


DNP3 supports end-to-end encryption via Virtual Private Network (VPN) tunnels or Transport Layer Security (TLS) encryption. DNP3 also supports authentication and implementation or role-based access controls. 


Open Platform Communications


Open Platform Communications (OPC) is an open-standard communications protocol evolved from the earlier Object Linking and Embedding (OLE) implementation for process control. The purpose of OPC is to act as an abstraction layer between Human-Machine Interface (HMI) or SCADA systems and Programmable Logic Controllers (PLC) that may be relying on several different protocols, such as Modbus or PROFIBUS. 


Essentially, the control and monitoring devices, such as HMI and SCADA servers, communicate directly with OPC servers using the OPC protocol. The OPC server then translates the commands to the appropriate protocol (for example, Modbus or PROFIBUS) in order to communicate with target devices, such as a PLC or actuator. 


OPC can provide security through encrypted communications, the use of digital certificates, and enforcing authentication and authorization.


WirelessHART


WirelessHART (where HART is an acronym for Highway Addressable Remote Transducer) is a protocol that uses a 2.4-gigahertz (GHz) wireless mesh network to communicate with field devices. WirelessHART has a communication range of 200 meters between each device and can be an excellent way to connect field devices when physical connections are not feasible. WirelessHART enforces Advanced Encryption Standard (AES)-128 encryption for device communication.



-----------------

Industrial Control System Protocol Security
From a cybersecurity perspective, the majority of ICS protocols and applications lack what are considered standard security controls in modern enterprise networks. 

﻿

Many ICS protocols were designed before widespread adoption of modern network-based communication technologies. Prior to the internet, ICS systems were isolated within a plant and required physical access to control and monitor them. These legacy protocols typically relied on direct serial connections between HMIs, PLCs, and end devices. Because these systems were traditionally air gapped, security was not a consideration when the protocols were developed. 

﻿

As modern network technologies became widely adopted in corporate environments, organizations began to converge IT and Operational Technology (OT) environments. Legacy ICS protocols were adapted to support transport over Ethernet and IP networks, but they were not always updated to include common security controls, such as authentication and encryption. 

﻿

Modbus is an example of an ICS protocol that was updated to enable transport over IT networks. Modbus TCP communications are sent as cleartext between a client and server over the network. If an attacker were present on a Modbus TCP network, they could eavesdrop on device communications to view commands and responses. Additionally, Modbus TCP does not support authentication or authorization technologies. This means that any properly formatted Modbus TCP message is accepted and processed by an ICS device that uses Modbus TCP. In this case, an attacker can easily send commands to control field devices or send incorrect sensor values to an HMI monitoring a process. 

﻿

In addition to insecure protocols, many ICS networks use applications and servers that lack basic security controls. These applications were traditionally deployed by controls engineers without an IT or cybersecurity background. This can result in such applications as databases or web servers being deployed with default configurations and left unauthenticated. It is also reasonable to assume that these applications and the servers that host them are older, unpatched systems. In some cases, these assets may be intentionally deployed without authentication. Consider an HMI terminal that controls a critical process. Failure to properly authenticate with the HMI may result in a lockout that prevents an OT engineer from controlling the process. In OT environments, availability of critical assets and processes is almost always prioritized over the implementation of a security control. 

﻿

Another contributing factor to the lack of security controls in ICS environments is vendor requirements for warranties and support contracts. Many Distributed Control Systems (DCS) consist of several components, such as control software, HMIs, preconfigured PLCs, and field devices. All these components are built and tested by the vendor before they are installed in an organization’s ICS environment. Updating Operating Systems (OS) or making configuration changes alters the vendor’s baseline and might affect a system’s ability to operate properly. Such changes are generally prohibited by the vendor. Instead, the only authorized changes or updates are those specifically supplied by the vendor as part of a support contract. Such product updates may have extremely long lead times. In some cases, receiving critical security updates from a vendor may take years. 


------------------

Control a PLC with Modbus
The following lab provides a simulated PLC that controls a voltage regulator. Using a command line–based Modbus tool, complete the steps in the workflow to remotely control the PLC. This lab demonstrates how an attacker can take advantage of the lack of security in the Modbus protocol to manipulate control system processes.

﻿

Workflow
﻿

1. Open the Virtual Machine (VM) win-hunt. The login credentials are as follows:


Username: trainee
Password: CyberTraining1!
﻿

2. Select the ModbusPal desktop shortcut.

﻿

3. Import the PLC simulation project file by selecting the Load button and opening the file PLC_Simulation.xmpp located in C:\users\trainee\Documents:


﻿<img width="300" height="403" alt="image" src="https://github.com/user-attachments/assets/e36a3de2-8b60-4e44-b35e-94aafcee0d02" />


<img width="472" height="365" alt="image" src="https://github.com/user-attachments/assets/801927ab-9859-4aad-907e-85bdd758532a" />

4. Activate the simulation by selecting the Play button to start the automation, and select Run to start the Modbus server. Select the eye icon to the right of the PLC object to view the PLC settings


<img width="446" height="601" alt="image" src="https://github.com/user-attachments/assets/391bf8c0-5203-4afe-86ce-1e7a2b9d7678" />

By default, the existing holding registers are displayed. In Modbus, holding registers are used to represent values obtained by reading sensors or to configure set points for a process. The three main fields of interest are Address, Value, and Name. The Address field is used when sending Modbus commands to the PLC to specify the register that is to be read or changed. The Value field displays what the register is currently set to. The Name field, also known as a tag, provides context to associate the register with the part of the physical process it controls. The Name field is only locally significant, meaning this is not a field that can be remotely queried using Modbus commands. 


For this example, registers 1 through 4 are in use. The first register represents a reading of input voltage to the voltage regulator. Because this register is reading a sensed value, it fluctuates as the input voltage changes. The OutputVoltage register is a configured set point that specifies what voltage the regulator should maintain; in this case, the regulator is configured to output 120 volts (V). The MinVoltage and MaxVoltage are used as safety settings that should trigger an alert if the output voltage goes below 110 V or above 130 V.


<img width="419" height="429" alt="image" src="https://github.com/user-attachments/assets/6ee9e161-00e3-4c6d-8f41-614bed3403b7" />

5. Select the Coils tab to view the configured coils.


Modbus coils differ from registers in that they are binary and represent a condition of on (1) or off (0). Coils are typically used to set or read the condition of a switch or a feature. In this example, the OutputEnabled coil is set to 1, which means the voltage regulator is turned on and outputting voltage. The SafetyOverride coil represents a setting that would disable the generation of alerts if the MinVoltage or MaxVoltage thresholds were breached. (This feature is currently disabled.)

<img width="421" height="429" alt="image" src="https://github.com/user-attachments/assets/9b9c3320-5d71-4b0a-9d81-96e6a5d0b1c2" />
6. Select the run_ctmodbus.bat desktop icon to open the ctmodbus tool.


A ctmodbus command prompt appears.


7. In the ctmodbus terminal, run the help command. 


This displays a list of available commands and brief descriptions of their operation. Select Enter again to acknowledge the help dialog and return to the prompt: 


<img width="676" height="372" alt="image" src="https://github.com/user-attachments/assets/30fb4a11-b786-4aa0-be87-0b4453f0de9e" />

8. Run the following command to open a session with the Modbus simulator: 


connect tcp 127.0.0.1:502



9. Once connected, a Success message appears. Select the Enter key to acknowledge the message and return to the prompt:


<img width="319" height="149" alt="image" src="https://github.com/user-attachments/assets/95656e86-3863-4020-89d6-9bdd921ba594" />


Authentication is not required to send commands to the PLC.


The read holdingRegisters command can be used to query the holding register values of the PLC. To use the command, provide the holding register addresses to be queried. The numbering of holding register addresses on the PLC is different from what Modbus uses when sending commands. On the PLC address, numbering starts with 1, but with Modbus commands, register addresses start at 0. 


10. Run the following command to read the values for the first five holding registers on the PLC:


read holdingRegisters 0-4



11. Compare the output from the read holdingRegisters command to the holding registers displayed in the PLC.


Addresses 0–4 in the command output correspond with addresses 1–5 on the PLC. Also, as previously mentioned, the register names, or tags, are not provided in the output. This means that an attacker can query all the registers and obtain the current values, but they do not know what each register represents


<img width="282" height="271" alt="image" src="https://github.com/user-attachments/assets/e385ab9e-face-4522-8a26-a075773525f2" />


<img width="419" height="429" alt="image" src="https://github.com/user-attachments/assets/3c12a260-5277-45fd-8dfd-ca6892d3af19" />

The read coils command operates just like the read holdingRegisters command. Provide the addresses of the coils to be read. Again, coil addressing in Modbus starts at 0.


12. Run the following command to read the first two coil values on the PLC:


read coils 0-1



The returned coil values match what is displayed on the PLC


<img width="207" height="225" alt="image" src="https://github.com/user-attachments/assets/ab1ac914-ef58-4c18-8550-236ec791e852" />

<img width="421" height="429" alt="image" src="https://github.com/user-attachments/assets/b15ee9f8-8038-4be9-b455-6d1893f513d0" />

Registers and coils can also be modified remotely by using the write command. The syntax for this command is as follows:


write (register|coil) (address) (value)



13. Run the following command to increase the MaxVoltage holding register value to 240 V: 


write register 3 240



The PLC now displays the updated value of 240



<img width="250" height="144" alt="image" src="https://github.com/user-attachments/assets/baed4f9c-1752-48ec-9805-9d80226042d6" />


<img width="418" height="430" alt="image" src="https://github.com/user-attachments/assets/0a9356a2-80b1-4ec3-a999-6b9e86ce217f" />

14. Run the following command to configure the PLC’s OutputVoltage to 220 V:


write register 1 220



The PLC is now set to deliver an output voltage of 220 V. This configuration would create an overvoltage situation that could cause physical damage to equipment


<img width="249" height="142" alt="image" src="https://github.com/user-attachments/assets/0e44a869-27c8-4442-9c16-bc0df2965dc7" />

<img width="416" height="427" alt="image" src="https://github.com/user-attachments/assets/588ae4cd-23c9-45de-95eb-410e770f2b8d" />

15. Run the following command to turn on the safety override:




write coil 1 1



The SafetyOverride coil has now been enabled, which disables the safety system, creating yet another dangerous situation for this control system


<img width="260" height="144" alt="image" src="https://github.com/user-attachments/assets/689c18aa-2bae-4bb9-9e6f-f59f755bf344" />


<img width="418" height="429" alt="image" src="https://github.com/user-attachments/assets/040330a6-77b6-4827-9cfa-cfd15a0d392d" />

----------------


### CDAH-M29L3-Availability and Visibility in ICS ###

ICS Host Analysis Tools
Host analysis tools are used in an ICS environment to gather information about the host computer or device on which the ICS runs. 

﻿

Host Analysis tools gather information such as the following:

Installed software 
Network configurations
System-level details
This information is used to identify vulnerabilities and potential security risks in the ICS, and to understand the overall configuration of the system. 

﻿

Host analysis tools are also used to monitor a system for changes and to detect suspicious activity. An example of this would be a software program that runs on individual devices within an ICS environment, gathers data, and analyzes the state of the system during a cyber incident. 

﻿

There are differences between the analysis tools used in ICS and those used in IT environments.

﻿

ICS Environments 
﻿

ICS analysis tools are designed to work with the specialized hardware and software tools used in industrial environments. These tools typically have features for working with Programmable Logic Controllers (PLC) and other industrial control systems. 

﻿

ICS tools also have features for interacting with field devices and sensors used to gather data from the physical environment, as seen in Figure 29.3-1 below:


<img width="3324" height="1878" alt="image" src="https://github.com/user-attachments/assets/8f435b87-efa7-4f02-8208-32f4cd287a76" />

IT Environments


IT analysis tools are generally designed to work with standard IT hardware and software, such as servers, desktop computers, and networks. These tools may have features for working with common IT protocols and services such as Transmission Control Protocol (TCP), Internet Protocol (IP), and Active Directory (AD).


Modern ICS environments consist of a combination of specialized ICS devices and commodity IT hardware and operating systems. The integration of IT components in ICS networks provides the opportunity to use traditional IT IR tools when investigating a compromised ICS environment. 


However, it is common for the IT components in an ICS environment to be outdated legacy systems that are incompatible with newer host analysis tools and software. For example, imagine trying to use PowerShell to query a 20-year-old WindowsXP device. 


While there is some overlap between the functionality of ICS and IT analysis tools, they are designed to address different types of hardware, software, and security concerns. Due to the differences between ICS and IT analysis tools, incident response in ICS environments often requires specialized knowledge and expertise that may not be required in IT environments.


------------

ICS Host Analysis Constraints
In many cases, analysts do not have permission to deploy collection sensors or agents in a mission partner’s ICS environment. In these situations, analysts have to rely on offline artifact analysis to investigate the potential compromise of ICS networks. 

﻿

For offline analysis, use forensics acquisition tools that perform functions such as the following: 

Disk imaging
Memory image capture
Artifact extraction
Once artifacts are gathered, they can be loaded onto a dedicated forensics workstation, or offline SIEM for analysis.

﻿

As seen in Figure 29.3-2 below, there are several constraints that may prevent an analyst from running host analysis and forensic acquisition tools on ICS components. 



<img width="1600" height="872" alt="image" src="https://github.com/user-attachments/assets/fa64727b-9adb-4783-880a-b1e65e829c1b" />



Operational Constraints


ICS components are often critical to the operation of a facility or process, and running forensic acquisition tools on these components may disrupt or interfere with their normal operation. In some cases, it is not possible to shut down or disconnect the ICS components in order to perform the forensic acquisition, which can make it difficult or impossible to gather the necessary data.


Physical Constraints


ICS components are often located in remote or difficult-to-access locations, such as in underground mines, offshore oil platforms, or remote substations. In such cases, it may be difficult or impossible for an analyst to physically access the components in order to perform the forensic acquisition. 


Technical Constraints


Many ICS components use specialized hardware and software that may not be compatible with standard forensic acquisition tools. This can make it difficult or impossible for an analyst to gather the necessary data from the components using standard techniques.


Safety Constraints


Some ICS components may be located in hazardous environments, such as in nuclear power plants or chemical processing facilities, where the use of forensic acquisition tools may pose a safety risk to the analyst.


These constraints pose a unique challenge to host analysts that are responding to an incident in an ICS environment. In an ICS incident response scenario, analysts must work closely with the mission partner to identify the best opportunities for artifact collection within the ICS


-------------

ICS Remediation
During the IR process, once a compromise has been identified, the team moves to contain and eradicate the threat. In IT networks, this can involve isolating infected hosts with access controls, or physically disconnecting the hosts from the network. 

 ﻿

Once containment has been achieved, the team attempts to eradicate the infection by performing the following actions: 

Device replacement
Reverting the device to a known good state
Re-imaging the device
Critical Processes
﻿

In an ICS network, it may not be possible to disconnect and replace infected components that are part of a critical process. When an infected ICS component is part of a critical process, and cannot be replaced until a scheduled maintenance window is available, ICS networks may need to remain in the containment phase for an extended period of time. 

﻿

In such cases, the main goal of containment is to minimize the attacker's ability to cause damage to the critical process while still allowing the process to operate. This can be achieved by implementing security controls such as network segmentation and access control lists. 

﻿

ICS Devices
﻿

To further complicate matters, it may not be possible to make configuration changes that support containment on the infected device itself. ICS device configuration is often tightly controlled. Therefore, changes to the configuration may invalidate the vendor-approved operating baseline and cause system instability. 

﻿

Additionally, the ICS device may not be equipped with the appropriate utilities to support containment, such as a host-based firewall. It may be necessary to make the containment and isolation configuration on network devices such as switches, routers, or firewalls.


---------------------

IR Practices and ICS Systems, Part 1
A mission partner that operates a chemical processing plant has detected malicious cyber activity in their enterprise IT network. The mission partner is concerned that the attacker has moved laterally from the enterprise IT network to the ICS network. The mission partner has requested a threat hunting team to investigate the ICS network for signs of compromise. Due to the critical nature of the ICS system, all analysis will be performed offline using datasets provided by the mission partner. 

﻿

Workflow
﻿

The mission partner has provided a GRASSMARLIN capture of baseline traffic flows in the ICS network that can be used as a starting point for the investigation. ICS network traffic is useful for baselining because it is extremely deterministic and predictable. 

﻿

Use GRASSMARLIN to investigate new connections detected in the ICS network that deviate from the baseline.

﻿

1. Log in to the Virtual Machine (VM) win-hunt with the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Select the GrassMarlin shortcut on the Desktop.

﻿

3. Select File, and then select Open Session.

﻿

4. Select baseline.gm3 from the Desktop/Case folder, and then select Open. 

﻿

Observe the baseline communications present in the ICS network, as seen in Figure 29.3-3 below:


<img width="978" height="725" alt="image" src="https://github.com/user-attachments/assets/65f42c03-ea32-4cdb-b7e2-6a8750b9948b" />

5. Open the post_exploit.gm3 file by repeating Step 3 and Step 4. Select No when prompted to save the current file. 


Keep this VM open for use in the upcoming workflow. 


Compare the baseline and post_exploit environments to answer the following questions. 



-------------

IR Practices and ICS Systems, Part 1
A mission partner that operates a chemical processing plant has detected malicious cyber activity in their enterprise IT network. The mission partner is concerned that the attacker has moved laterally from the enterprise IT network to the ICS network. The mission partner has requested a threat hunting team to investigate the ICS network for signs of compromise. Due to the critical nature of the ICS system, all analysis will be performed offline using datasets provided by the mission partner. 

﻿

Workflow
﻿

The mission partner has provided a GRASSMARLIN capture of baseline traffic flows in the ICS network that can be used as a starting point for the investigation. ICS network traffic is useful for baselining because it is extremely deterministic and predictable. 

﻿

Use GRASSMARLIN to investigate new connections detected in the ICS network that deviate from the baseline.

﻿<img width="1917" height="827" alt="image" src="https://github.com/user-attachments/assets/a228f4c8-3bf2-45b2-88a1-a315082573b3" />

---------------------

IR Practices and ICS Systems, Part 2
Comparing the baseline and current network traffic reveals that there is a new connection between 172.16.79.35 and a device outside of the ICS network. A network map provided by the mission partner, as seen in Figure 29.3-4 below, shows that the 172.16.79.35 device is the control system data historian server. 

﻿

A data historian is a centralized database used in ICS networks to collect health and performance data from control system devices. The mission partner also confirmed that the 172.16.4.20 IP address is part of a client workstation subnet in the enterprise IT network. The mission partner highlighted that this communication path is abnormal. 

﻿<img width="2048" height="2048" alt="image" src="https://github.com/user-attachments/assets/6fa81ae4-9963-463e-805d-079dd6a2afd2" />


Use the event logs in the Desktop/Case/Logs directory to continue the investigation.


Workflow


1. Log in to the VM win-hunt with the following credentials:
Username: trainee
Password: CyberTraining1!



2. If open, close GRASSMARLIN. Select Close, and then select No when prompted to save changes.


3. Navigate to the Desktop/Case/Logs directory and open sysmon.evtx in Windows Event Viewer.


4. Select the Date and Time column header to sort the events from oldest to newest. Navigate to the first event.


Sysmon provides valuable log information pertaining to file creation, process creation, and network connections. This log source can help identify the process that is communicating with the external host 172.16.4.20.


5. Select the Find icon in the Action pane. 


6. Enter the following destination IP address:
172.16.4.20



7. Select Find Next.


Event Viewer moves to the first log that contains the IP address of 172.16.4.20. 


8. Click Close on the Find dialog box.


As seen in Figure 29.3-5, below, the network connection log displays several pieces of information that are useful for further investigation such as the filename, the location where payload.exe was created, the SourceIp, and more. 

<img width="661" height="826" alt="image" src="https://github.com/user-attachments/assets/626af6af-98c2-4ad8-8f5e-79cfc3113edd" />


Knowledge Check
Sysmon generates a log entry when a new process is created. This log is represented by Event ID 1.

﻿

Find the Process Create Sysmon log associated with payload.exe to answer the following question. 

﻿

Question:
﻿

What is the MD5 Hash of payload.exe?

<img width="1085" height="607" alt="image" src="https://github.com/user-attachments/assets/9304d03f-59fb-4fca-a6c1-6dd5d31a3b41" />


Knowledge Check
Sysmon generates a log entry whenever a new file is created. This log is represented by Event ID 11.

﻿

Find the Sysmon log associated with payload.exe to answer the following question.

﻿

Question:
﻿

At what UTC time was the payload.exe file created?
﻿
<img width="1127" height="574" alt="image" src="https://github.com/user-attachments/assets/c156f8e8-23f0-4232-877d-60b01b2f1c64" />


Knowledge Check
Migrating to already-running processes is one method that an attacker uses to avoid detection. Sysmon Event ID 8 can aid in the detection of process migration techniques. 

﻿

Find the Sysmon CreateRemoteThread Detected log associated with payload.exe to answer the following question.

﻿

Question:
﻿

What is the filename of the TargetImage that the attacker migrated into? 

<img width="1131" height="474" alt="image" src="https://github.com/user-attachments/assets/d05652ee-624d-48f6-a271-b0b4bd5935fc" />


Knowledge Check
﻿

The compromised ICS host, 172.16.79.35, and the running vmtoold.exe process represent critical components of the mission partners OT network.

﻿

The mission partner requires a course of action that stops the identified malicious cyber activity while maintaining the highest level of availability for the ICS host, and the vmtoolsd.exe process. The mission partner stated that changes to the existing server configuration must be avoided due to vendor requirements. 

﻿

Question:
﻿

Which action should the mission partner perform?
