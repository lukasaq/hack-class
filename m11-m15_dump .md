Here’s a summary of all the commands found in the file m11-m15_dump .md from lukasaq/hack-class, including descriptions, syntax examples, and the relevant switches/parameters:

---

## 1. Invoke-RestMethod (PowerShell)

**Description:**  
A PowerShell cmdlet used to send HTTP and REST API requests (GET, POST, etc.) from scripts or the command line, and receive the responses. Supports headers, body data, authentication, proxies, and more.

**Syntax Example (GET):**
```powershell
$response = Invoke-RestMethod  http://site.com/people/1
```

**Syntax Example (GET with Headers):**
```powershell
$headers = New-Object "System.Collections.Generic.Dictionary[String,String]"
$headers.Add("X-DATE", '9/29/2014')
$headers.Add("X-SIGNATURE", '234j123l4kl23j41l23k4j')
$headers.Add("X-API-KEY", 'testuser')
$response = Invoke-RestMethod 'http://site.com/people/1' -Headers $headers
```

**Syntax Example (POST with JSON Body):**
```powershell
$person = @{
   name='steve'
}
$json = $person | ConvertTo-Json
$response = Invoke-RestMethod 'http://site.com/people/1' -Method Post -Body $json -ContentType 'application/json'
```

**Common Parameters & Switches:**

- -Uri (or first unnamed parameter): Target URL
- -Method: GET (default), POST, PUT, DELETE, etc.
- -Headers: Dictionary/hashtable of HTTP headers
- -Body: Content to send (e.g., JSON, XML)
- -ContentType: MIME type (e.g., application/json)
- -Proxy, -Credential, -TimeoutSec, etc.

---

## 2. schtasks (Windows Command-Line)

**Description:**  
Schedules and manages tasks to run programs or scripts periodically or in response to specific events in Windows.

**General Syntax:**
```cmd
schtasks /create [options]
```

**Examples:**

- Run at every system start after a certain date:
  ```cmd
  schtasks /create /tn My App /tr c:\apps\myapp.exe /sc onstart /sd 03/15/2020
  ```
- Run with system permissions on the 15th of each month:
  ```cmd
  schtasks /create /tn My App /tr c:\apps\myapp.exe /sc monthly /d 15 /ru System
  ```
- Create remote task to run every 10 days:
  ```cmd
  schtasks /create /s SRV01 /tn My App /tr c:\apps\myapp.exe /sc daily /mo 10
  ```
- Run on specific event (Event ID 4647 - user logs off):
  ```cmd
  SCHTASKS /Create /TN test2 /RU system /TR c:\apps\myapp.exe /SC ONEVENT /EC Security /MO "*[System[Provider[@Name='Microsoft Windows security auditing.'] and EventID=4647]]"
  ```

**Key Switches & Parameters:**

- /create           : Create a new scheduled task
- /tn <name>        : Task name
- /tr <path>        : Task to run (full path)
- /sc <schedule>    : Schedule type (MINUTE, HOURLY, DAILY, WEEKLY, MONTHLY, ONCE, ONSTART, ONLOGON, ONIDLE, ONEVENT)
- /sd <date>        : Start date
- /d <day>          : Day (for monthly)
- /ru <user>        : Run as user (System, etc.)
- /s <computer>     : Target computer (for remote)
- /mo <modifier>    : Modifier (interval, or event filter)
- /ec <log>         : Event log (e.g., Security)
- /?                : Show help

---

## 3. PowerShell JSON Utilities

**Description:**  
Convert PowerShell objects to and from JSON, often used with REST APIs.

**Syntax Example:**
```powershell
ConvertTo-Json
# Usage:
$json = $person | ConvertTo-Json
```
- Converts a PowerShell object to JSON format.

**To save query results to a JSON file:**
```powershell
$results | ConvertTo-Json -Compress | Set-Content <File Path\FileName.json>
```

- -Compress: Minifies the JSON output.

---

## 4. Example ElasticSearch Query (not a direct command, but REST API usage)

**Description:**  
The file shows how to compose queries for ElasticSearch using RESTful syntax, which can be run via Dev Tools (in Elastic UI), cURL, or PowerShell (with Invoke-RestMethod).

**Example Query:**
```json
GET _search
{
  "query": {
    "bool": {
      "must": [
        {"match":{"winlog.event_id.keyword":"8"}},
        {"match":{"agent.name":"eng-wkstn-3"}},
        {"range":{
          "@timestamp":{
            "gte":"2022-04-19T00:30:00.000Z",
            "lte":"2022-04-19T23:30:00.000Z"
          }
        }}
      ]
    }
  }
}
```
This is typically sent as the body in a REST API request.

---

## Summary Table

| Command                | Description                                                                 | Syntax Example (see above)                | Key Switches/Parameters (see above)      |
|------------------------|-----------------------------------------------------------------------------|-------------------------------------------|------------------------------------------|
| Invoke-RestMethod      | PowerShell cmdlet for HTTP/REST requests                                    | GET/POST with -Headers/-Body/-ContentType | -Uri, -Method, -Headers, -Body, etc.     |
| schtasks               | Windows command-line task scheduler                                         | /create /tn /tr /sc /sd /ru /mo           | See full list above                      |
| ConvertTo-Json         | PowerShell utility to convert objects to JSON                               | -Compress                                 | -Compress                                |
| Set-Content            | PowerShell cmdlet to write output to a file                                 |                                           | File path                                |

---

Do you want detailed tables of parameters for schtasks or Invoke-RestMethod? If so, specify which command or both.
