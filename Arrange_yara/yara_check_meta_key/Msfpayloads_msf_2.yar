rule Msfpayloads_msf_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-09"
    description = "Metasploit Payloads - file msf.asp"
    family = "None"
    hacker = "None"
    hash1 = "e52f98466b92ee9629d564453af6f27bd3645e00a9e2da518f5a64a33ccf8eb5"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "& \"\\\" & \"svchost.exe\"" fullword ascii
    $s2 = "CreateObject(\"Wscript.Shell\")" fullword ascii
    $s3 = "<% @language=\"VBScript\" %>" fullword ascii
  condition:
    all of them
}