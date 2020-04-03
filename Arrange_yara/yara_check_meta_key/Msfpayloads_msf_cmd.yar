rule Msfpayloads_msf_cmd {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-09"
    description = "Metasploit Payloads - file msf-cmd.ps1"
    family = "None"
    hacker = "None"
    hash1 = "9f41932afc9b6b4938ee7a2559067f4df34a5c8eae73558a3959dd677cb5867f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "%COMSPEC% /b /c start /b /min powershell.exe -nop -w hidden -e" ascii
  condition:
    all of them
}