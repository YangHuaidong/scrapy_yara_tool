rule Msfpayloads_msf_psh {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-09"
    description = "Metasploit Payloads - file msf-psh.vba"
    family = "None"
    hacker = "None"
    hash1 = "5cc6c7f1aa75df8979be4a16e36cece40340c6e192ce527771bdd6463253e46f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "powershell.exe -nop -w hidden -e" ascii
    $s2 = "Call Shell(" fullword ascii
    $s3 = "Sub Workbook_Open()" fullword ascii
  condition:
    all of them
}