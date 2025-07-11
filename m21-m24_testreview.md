

---

## ✅ **"21 Questions — 2 Hours" Cybersecurity Task List**

- Being able to run commands to see interfaces online and how to disable or enable them  
- Hash values of a file — Algorithm: **MD5**  
- Be able to examine the system and look for suspicious activity  
- Look for suspicious commands in Linux like `ps -ef`, and examine processes to detect anomalies; can use `find` or `grep`  
- Look at different types of scripts, whether they are Python or PowerShell, and understand what they do  
- Use `tasklist` and `netstat` to look for remote connections  
- Use **Kibana** to find malicious traffic, identify IPs, ports, and processes  
- Be able to find different types of persistence methods — registry keys, scheduled tasks, or startup entries  
- Look at documents for macros and run commands to find what type of information is embedded  
- Use **FakeNet** to analyze packets and look for indicators  
- Look at documents that contain macros and identify malicious behavior  
- Use **Kibana** to determine which machines have been infected  
- Understand types of mitigations suggested by CIS Benchmarks; update scripts to enforce these values  
- Use **Metasploit** for penetration testing and exploit research

---


---

## 🧠 "21 Questions in 2 Hours" Cybersecurity Task List

### 🖧 Network Interface Management
- Run commands to view online interfaces and enable/disable them:  
  - Linux: `ip a`, `ifconfig`, `sudo ifconfig eth0 down/up`  
  - Windows: `Get-NetAdapter`, `Disable-NetAdapter`

### 🔐 File Hash Verification
- Generate and verify MD5 hash values of files:  
  - Linux: `md5sum filename`  
  - Windows: `CertUtil -hashfile filename MD5`

### 🕵️ System Activity & Suspicious Behavior
- Examine systems for suspicious activity  
- Use commands like:
  - `ps -ef | grep <keyword>` to inspect running processes  
  - `find / -name <file>` to locate suspicious files  
  - `grep -i 'suspicious' *.log` to scan logs

### 🧾 Script Behavior Analysis
- Review Python and PowerShell scripts  
  - Check for suspicious imports and obfuscation  
  - Inspect execution patterns: file writes, network calls, subprocess

### 📡 Monitor Remote Connections
- Use `tasklist` to view active tasks (Windows)  
- Use `netstat -ano` or `ss -tulnp` to check open ports and connections  
- Identify unknown remote IPs or services

### 📊 Traffic & Malware Detection via Kibana
- Detect malicious traffic by identifying:  
  - Unusual IP addresses and ports  
  - Unexpected spikes in traffic  
  - Processes associated with infected machines

### 🧬 Persistence Mechanism Discovery
- Identify persistence methods:  
  - Windows Registry: `reg query`  
  - Scheduled tasks: `schtasks /query` or `crontab -l`  
  - Startup folder items

### 📄 Macro Document Investigation
- Analyze documents with embedded macros  
  - Use tools like `olevba`  
  - Search for suspicious calls (e.g. `Shell`, `CreateObject`, `AutoOpen`)

### 📦 Packet Analysis with FakeNet
- Use **FakeNet-NG** to simulate network services  
- Capture outbound traffic attempts  
- Use `Wireshark` for packet-level analysis

### ⚠️ Macro Document Malware Detection
- Identify "BAD" macros:  
  - Suspicious auto-launch functions  
  - Encoded payloads or external command execution  
  - Indicators like `"powershell"`, `"wget"`, `"curl"`

### 🖥️ Infection Mapping in Kibana
- Determine which machines are infected by:  
  - Correlating IPs, processes, and traffic  
  - Matching known indicators of compromise (IOCs)

### 🛡️ CIS Benchmark Mitigation Strategies
- Apply security hardening updates:  
  - Use automated scripts to enforce password policies, disable unused services  
  - Reference CIS Benchmarks for secure configurations

### 🔧 Metasploit Usage
- Launch penetration tests with **Metasploit**:  
  - `msfconsole`, `search exploit`, `use <module>`  
  - Ensure testing is done in a controlled lab environment

---


