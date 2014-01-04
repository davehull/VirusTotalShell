VirusTotalShell
=============

A fork of David B Heise's VirusTotal Powershell Module
http://psvirustotal.codeplex.com/SourceControl/latest#VirusTotal.psm1

##Example Usage
```
PS E:\hunt\data> Import-Module .\VirusTotal.psm1
PS E:\hunt\data> Get-Command -Module VirusTotal

CommandType     Name                                               ModuleName
-----------     ----                                               ----------
Function        Get-VTApiKey                                       VirusTotal
Function        Get-VTReport                                       VirusTotal
Function        Invoke-VTRescan                                    VirusTotal
Function        Invoke-VTScan                                      VirusTotal
Function        New-VTComment                                      VirusTotal
Function        Set-VTApiKey                                       VirusTotal

PS E:\hunt\data> Set-VTApiKey -VTApiKey yourVTAPIkeyhere

PS E:\hunt\data> Get-Help Get-VTReport

NAME
    Get-VTReport

SYNTAX
    Get-VTReport [-VTApiKey <string>] [-hash <string>]  [<CommonParameters>]

    Get-VTReport [-VTApiKey <string>] [-file <FileInfo>]  [<CommonParameters>]

    Get-VTReport [-VTApiKey <string>] [-uri <uri>]  [<CommonParameters>]

    Get-VTReport [-VTApiKey <string>] [-ip <string>]  [<CommonParameters>]

    Get-VTReport [-VTApiKey <string>] [-domain <string>]  [<CommonParameters>]


ALIASES
    None


REMARKS
    None
```
You can combine this script with the output from something like https://github.com/davehull/Get-StakRank#get-stakrank or hashes from Autorunsc.exe and do useful things like:
```
PS E:\hunt\data> $data = Import-Csv -Delimiter "`t" '.\FIN-Image Path-MD5.tsv' 
PS E:\hunt\data> $data | ? { $_.Count -lt 10 -and $_.MD5.length -gt 3 } | select -unique MD5 -ExpandProperty MD5 | % { Get-VTReport -hash $_ | select scan_date, positives, resource, verbose_msg, permalink; sleep 15 }
```
This will return something like the following:
```
scan_date   :
positives   :
resource    : 06f12e6478246b0f7ef11f2a6735b876
verbose_msg : The requested resource is not among the finished, queued or pending scans
permalink   :

scan_date   :
positives   :
resource    : 04113bb90f3c162ebd961a3065c15fe1
verbose_msg : The requested resource is not among the finished, queued or pending scans
permalink   :

scan_date   : 2013-06-10 14:19:55
positives   : 0
resource    : bf68a382c43a5721eef03ff45faece4a
verbose_msg : Scan finished, scan information embedded in this object
permalink   : https://www.virustotal.com/file/09eba33e313cf8f19c5a2d19ada286e9fdd09c6a99f6bf77b65fa55cc6061590/analysis/1370873995/

scan_date   : 2013-11-06 03:43:51
positives   : 0
resource    : 5534ed475c61188fffa4168f28a0d893
verbose_msg : Scan finished, scan information embedded in this object
permalink   : https://www.virustotal.com/file/10d3f4a431f259164f8abeb158381db92cbb9c02fd56e70addeab9907eb92e91/analysis/1383709431/

scan_date   : 2014-01-03 21:47:59
positives   : 1
resource    : a283e768fa12ef33087f07b01f82d6dd
verbose_msg : Scan finished, scan information embedded in this object
permalink   : https://www.virustotal.com/file/1d4d787047200fc7bcbfc03a496cafda8e49075d2fbf2ff7feab90a4fdea8f89/analysis/1388785679/
...
```
And of course, you can pipe this out to a file by running it as follows:
```
PS E:\hunt\data> $($data | ? { $_.Count -lt 10 -and $_.MD5.length -gt 3 } | select -unique MD5 -ExpandProperty MD5 | % { Get-VTReport -hash $_ | select scan_date, positives, resource, verbose_msg, permalink | ConvertTo-Csv -Delimiter "`t" -NoTypeInformation; sleep 15 } ) | Add-Content -Encoding Ascii vt-results.tsv
```
