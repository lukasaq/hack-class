#### CDAH-M11L1-PowerShell Fundamentals Review ####


To list all possible cmdlets in a system, the cmdlet Get-Command is extremely helpful. 
Get-Command -Type Cmdlet



For example, executing the Get-Member cmdlet on any directory object, such as a user’s Documents folder, returns the following output.
PS C:\Users\trainee> Get-Item ".\Documents\" | Get-Member

This cmdlet is used to retrieve a list of all scheduled tasks in the system. These are often a vector for adversary persistence or may be disabled by adversaries when the task runs scripts or programs to search for malicious activity. 

Get-ScheduledTask 

Get-ScheduledTask -TaskName Proxy | Format-List *


Get-Process | Where-Object {($_.ProcessName -like "*host*") -and ($_.CPU -lt 5) -and ($_.CPU -gt 0.01)


Select-String -Path "C:\path\to\file" -Pattern "pattern"



Get-Process | Where-Object -Property Name -match "explorer" | Format-Table Name, Description, Path, ID


Get-ScheduledTask | Where-Object {
    ($_ | Get-ScheduledTaskInfo).NextRunTime -like "7:00:00 AM"
}


#### CDAH-M11L2-Querying Active Directory with PowerShell ####

To effectively prevent this vulnerability, analysts may write a query that filters for accounts configured with the flag DONT_EXPIRE_PASSWORD set. In the AD user object, this flag is designated by the field passwordNeverExpires. The following query fulfills these requirements:
Get-ADUser -filter { passwordNeverExpires -eq $true -and enabled -eq $true } | Select Name, DistinguishedName


Invoke-Command -Session $session -ScriptBlock {Get-ADUser -filter * -properties DoesNotRequirePreAuth | where {$_.DoesNotRequirePreAuth -eq "TRUE"} | select samaccountname}

Get-ADUser -filter * -properties DoesNotRequirePreAuth | where {$_.DoesNotRequirePreAuth -eq "TRUE"} | select samaccountname

#### CDAH-M11L3-Cmdlet Use and Development ####

