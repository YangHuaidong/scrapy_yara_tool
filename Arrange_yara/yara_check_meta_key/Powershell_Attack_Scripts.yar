rule Powershell_Attack_Scripts {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-03-09"
    description = "Powershell Attack Scripts"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "PowershellMafia\\Invoke-Shellcode.ps1" ascii
    $s2 = "Nishang\\Do-Exfiltration.ps1" ascii
    $s3 = "PowershellMafia\\Invoke-Mimikatz.ps1" ascii
    $s4 = "Inveigh\\Inveigh.ps1" ascii
  condition:
    1 of them
}