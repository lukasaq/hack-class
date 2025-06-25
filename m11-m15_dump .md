
Integrating with RESTful APIs in PowerShell
A critical skill for Host Analysts is to develop custom tools and scripts that perform automated tasks for network communication between systems. Implementing network support in programming languages is typically complicated and time-consuming. However, PowerShell resolves these issues with cmdlets that support REST. REST defines a set of recommendations and constraints for network communication between web-based systems using Hypertext Transfer Protocol (HTTP).

﻿

Networked systems that adhere to the REST conventions are referred to as “RESTful”. PowerShell provides a RESTful API that facilitates client-server HTTP communications using the cmdlet invoke-restmethod. PowerShell connects to RESTful web services to easily integrate between custom scripts and existing systems on the network.

﻿

The next section explains how PowerShell supports the following:

Sending data to an HTTP server
Receiving data from an HTTP server
Using invoke-restmethod
Sending Data to an HTTP Server
﻿

PowerShell provides different methods to send a request to an HTTP server. Four methods are listed in Table 11.4-1, below. Individual web servers determine how to respond to these methods.



HTTP Request Data Options


An HTTP request includes the method, header, resource path, and body. The following table provides additional information about these components:







Another way to send data is with Uniform Resource Locator (URL) parameters or query strings. In these cases, additional key-value pairs are encoded in the resource path. This type of data passing allows a website to remember data between sessions. The following example URL includes two key-value pairs. The key query has a value of test and the key page has a value of 2:
http://domain.com/search?query=test&page=2


Receiving Data from an HTTP Server


Table 11.4-3, below, groups the different HTTP response codes into broad categories. The most well-known response code, 404 Not Found, is commonly displayed when URLs have a typo.



Using Invoke-RestMethod


Invoke-RestMethod is a robust cmdlet with many options including proxy, encryption, and compression support. Table 11.4-4, below, provides the basic options relevant to the labs in this lesson. One potential stumbling block is that PowerShell does not allow a user to send a GET request with a message body. Elastic allows the POST and GET requests to be used interchangeably, so any GET request that Elastic suggests can also be completed with a POST request.



Basic GET Request Example


The following command does not specify the options URI and Method:
$response = Invoke-RestMethod  http://site.com/people/1



The URI is assumed to be the first parameter provided and the default Method is Get. Omitting the parameter informs the cmdlet to do a Get request.


Headers Example


The following example creates a new dictionary object called $headers. This object uses the type String for both the key and value pairs:
$headers = New-Object "System.Collections.Generic.Dictionary[String,String]"
$headers.Add("X-DATE", '9/29/2014')
$headers.Add("X-SIGNATURE", '234j123l4kl23j41l23k4j')
$headers.Add("X-API-KEY", 'testuser')
$response = Invoke-RestMethod 'http://site.com/people/1' -Headers $headers



Post Example


JavaScript Object Notation (JSON) is an open standard that was originally intended for JavaScript, but has gained popularity in many other types of software. It is an alternative to various markup languages such as Extensible Markup Language (XML) and Yet Another Markup Language (YAML). JSON is commonly pronounced “Jay-sawn,” although “Jason” is also acceptable.


The body of the following request uses JSON format to define a single key-value pair of name-steve in the form of a hashtable. The hashtable is converted to a JSON and passed into the body of the RESTful method.
$person = @{
   name='steve'
}
$json = $person | ConvertTo-Json
$response = Invoke-RestMethod 'http://site.com/people/1' -Method Post -Body $json -ContentType 'application/json'



Conduct Elasticsearch Queries
Before conducting RESTful queries with PowerShell, it is helpful to first craft the queries using Elastic. Elastic Dev Tools provides a special interface for manually crafting and conducting queries. 

﻿

Conduct Elasticsearch Queries
﻿

Perform a query using the standard Elasticsearch interface, then use the Dev Tools interface to craft a RESTful query with Elastic. Use the information from this lab to answer the next question.

﻿

Workflow
﻿

1. Log in to the Virtual Machine (VM) win-hunt using the following credentials:

Username: trainee
Password: CyberTraining1!
﻿

2. Open Chrome.

﻿

3. Select the bookmark Sysmon_8_Query from the bookmarks bar. 

﻿

NOTE: If the message "Your connection is not private" is displayed, select Advanced and select the link Proceed to 199.63.64.92 (unsafe). Log in using the following credentials, then reselect the bookmark Sysmon_8_Query from the bookmarks bar:

Username: trainee@jdmss.lan
Password: CyberTraining1!
﻿

The following is the query from the bookmark. It searches for records based on event_id, agent.name and a time range. This query returns 6 results.

winlog.event_id.keyword:8 AND agent.name: eng-wkstn-3

Start: April 19th 2022 @ 00:30:00
Stop: April 19th 2022 @ 23:30:00 
﻿

4. Select the bookmark labeled Dev Tools - Elastic from the bookmarks bar. 

If the "Welcome to Console" message appears, select Dismiss.

The Dev Tools interface allows users to prototype RESTful commands. The interface accepts queries in the left pane and displays the results in the right pane. One critical difference between the RESTful interface and the previous search interface is that the RESTful interface uses a different set of logical operators, as listed below in Table 11.4-5:




5. Conduct a query for winlog.event_id.keyword: 8 in the dev API by entering the following input:
GET _search
{
  "query": {
    "bool": {
      "must": {
        "match":{"winlog.event_id.keyword":"8"}
      }
    }
  }
}



NOTE: The Elastic Dev Tools console attempts to predictively add brackets for interactive typing. When copying and pasting queries, ensure the pasted text matches the original and that additional brackets have not been added.


6. Run the query by selecting the green play icon in the upper right corner of the left pane.


The query results include all entries where winlog.event_id.keyword is equal to 8. Eighty records are returned, indicating 80 occurrences of event ID 8.




7. Refine the query in the dev API to only those entries that also have eng-wkstn-3 as the agent.name by entering the following:
GET _search
{
  "query": {
    "bool": {
      "must": [
        {"match":{"winlog.event_id.keyword":"8"}},
        {"match":{"agent.name":"eng-wkstn-3"}}
      ]
    }
  }
}



This modified query returns six entries where winlog.event_id.keyword equals 8 and agent.name equals eng-wkstn-3. 


8. Add a time range in the query that starts on April 19, 2022 at 00:30:00 and stops on April 19, 2022 at 23:30:00 by entering the following:
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



Although the results of the final query are limited to entries created within  the provid ed time range, it still returns only six hits. 



RESTful ElasticSearches with PowerShell
The previous lab demonstrated how to conduct manual RESTful queries using the Dev Tools interface. This knowledge helps construct PowerShell commands for the same queries. 

﻿

Conduct RESTful ElasticSearches with PowerShell
﻿

Convert the RESTful queries from the previous lab into a format for PowerShell to execute. Continue working in the VM win-hunt. 

﻿

Workflow
﻿

1. On the Elastic Dev Tools page, copy the query from the previous lab as a Client Uniform Resource Locator (cURL) command by selecting the wrench icon in the query input box and selecting Copy-as-cURL.

﻿

2. Use PowerShell ISE to open the file Elastic_PowerShell.ps1 from the desktop.

﻿

3. Paste in the cURL command at the end of the file.

﻿

NOTE: In this lab environment, the Secure Sockets Layer (SSL) certificates are not valid and require an additional step for PowerShell to make the connection. The script Elastic_PowerShell.ps1 provides code to account for certificates on the Elastic server.

﻿

4. Comment out the first line from the pasted cURL example in the script by adding # before curl, at the beginning of the line, and removing the single quote character from the very end of the pasted example. 

﻿

Only the query portion of the cURL command is necessary. The rest of the cURL command is useful to reference, but it is not executed.

﻿

5. Define the body content as a hash table and name the variable elastic_query by entering $elastic_query = @" at the beginning of the code block and "@ at the end, so that the entire block is displayed as follows:

$elastic_query = @"
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
"@
﻿

6. Define the headers as a hash table by entering the following syntax after the code block:

$headers = @{"Content-Type"="application/json"} 
﻿

7. Send a POST request to the same endpoint as the example cURL command, and store the results in a variable by adding a new line that starts with the cmdlet Invoke-RestMethod, as shown below:﻿

$results = Invoke-RestMethod "https://199.63.64.92:9200/_search" -Method POST -Headers $headers -Body $elastic_query



Unlike cURL, PowerShell does not send a GET request with a defined message body. Elastic allows for GET or POST to be used interchangeably for queries.

﻿

8. Select the Run Script icon above the editor window.

﻿

9. Confirm the number of records by running the following command on the interactive prompt:
﻿

$results.hits.total.value
﻿

The value displayed is 6.

﻿

The $results of a query can be stored in a JavaScript Object Notation (JSON) file. To store query results in a JSON file, use the following command syntax:

﻿

$results | ConvertTo-Json -Compress | Set-Content <File Path\FileName.json>  

﻿

Running queries on a regular basis and storing them may be used to build a baseline and detect future changes within the environment.



 PowerShell Execution Options
For PowerShell to execute code, something needs to tell Windows to execute the code. The best way to do this is by automating the code execution. There are different ways to automate code execution and they range from simple and functional, to more creative and customized. Some automation ideas include the following:

Setting registry keys that run code after a system boot.
Setting up the code to run as a service.
Building a custom application that is always running or "listening", so that it can either execute the script on a regular interval or after accepting a message that indicates it needs to start the PowerShell script. 
Despite the different ideas available, the most common way to automate code is with the built-in Windows scheduler, which this section explores.

﻿

Using the Windows Scheduler
﻿

The Windows command schtasks, an amalgamation of schedule and tasks, is responsible for the periodic execution of programs on a Windows system. The command is powerful and the options to run the command are complicated. To make this data more digestible, the information is broken down into several categories that focus on the creation of scheduled tasks.

﻿

Table 11.4-8, below, lists optional system connection options. The scheduled task defaults to the local computer, when the options listed are not specified. 




Table 11.4-9, below, lists options that are relevant for any task being created.




The next two tables apply based on whether a task is time-based or event-based. A time-based run option is for tasks that run on regular intervals. For example, running a task on the first Tuesday of each month, or every other week. An event-based option runs when a user logs on, when a system turns on, or based on specific event logs. 


Time-Based Options 


The syntax for time-based scheduling uses the schedule option tag followed by one of the time-based option keywords listed below:
/SC (MINUTE, HOURLY, DAILY, WEEKLY, MONTHLY)



Time based scheduled tasks execute the program specified at the desired interval. When a script does not need to be constantly executed, the script can be designed to check whether it is safe to execute before performing its task. For example, a script is created to update a zip file with local logs and send the zip file to a server. In this case, the script could save the last time it ran and compare that to the newest file in the directory. The advantage of this pattern is that the script execution can be handled by schtasks. The disadvantage is that running the script every 10 mins could cause a 10-minute delay for any new files getting shipped.


The following table provides additional information on time-based options.



Event-Based Options 


The syntax for event-based scheduling uses the schedule option tag followed by one of the event-based option keywords listed below:
/SC (ONCE, ONSTART, ONLOGON, ONIDLE, ONEVENT)



Event-based tasks are useful and powerful ways to launch a script. ONSTART, ONLOGON, and ONIDLE have their obvious uses. ONSTART is used when something needs to be done to the computer when it starts, regardless of the user. ONLOGON is useful for applying changes to a specific user. ONIDLE is useful when something needs to be run but interrupting the user is a concern. 


ONEVENT is a powerful tool because it allows a script to execute when a specific event log appears on the system. A use-case for this would be hunting for an adversary where forensically-relevant data is short-lived, but the initial detection of the event is known. As an example, imagine an adversary that was using tools that did not get written to disk, but it was known that the adversary would try to download a sensitive file. If object-access logging is enabled, and an XML Path Language (XPath) query string is made looking for specific access to a specific file, then that scheduled event could kick off a tool that dumps memory and ships off the threat actor's toolkit.


The following table provides additional information on event-based options.



Table 11.4-12, below, lists additional options that may be useful regardless of whether a task is time-based or event-based. 




Example schtasks commands


The following examples demonstrate different ways to create scheduled tasks with the command line tool schtasks.


Create a task that runs every time the system turns on after the 15th of March 2020:
schtasks /create /tn My App /tr c:\apps\myapp.exe /sc onstart /sd 03/15/2020



Create a task that runs with system permissions on the 15th of every month:
schtasks /create /tn My App /tr c:\apps\myapp.exe /sc monthly /d 15 /ru System



Create a remote task to run on system SRV01 every 10 days:
schtasks /create /s SRV01 /tn My App /tr c:\apps\myapp.exe /sc daily /mo 10



Create an event that runs myapp.exe whenever a user logs off (Windows Event ID 4647):
SCHTASKS /Create /TN test2 /RU system /TR c:\apps\myapp.exe /SC ONEVENT /EC Security /MO "*[System[Provider[@Name='Microsoft Windows security auditing.'] and EventID=4647]]"



NOTE: One reason this command is complicated is because the modifier option /MO is overloaded. This means that the values given to this parameter depend on the context of other parameters.
