rule Suspicious_PowerShell_WebDownload_1 {
  meta:
    author = Spider
    comment = None
    date = 2017-02-22
    description = Detects suspicious PowerShell code that downloads from web sites
    family = 1
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Internal Research
    score = 60
    threatname = Suspicious[PowerShell]/WebDownload.1
    threattype = PowerShell
    type = file
  strings:
    $s1 = "System.Net.WebClient).DownloadString(\"http" ascii nocase
    $s2 = "System.Net.WebClient).DownloadString('http" ascii nocase
    $fp1 = "NuGet.exe" ascii fullword
    $fp2 = "chocolatey.org" ascii
  condition:
    1 of ($s*) and not 1 of ($fp*)
}