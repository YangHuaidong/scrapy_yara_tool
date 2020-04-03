rule Msfpayloads_msf_exe {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-09"
    description = "Metasploit Payloads - file msf-exe.vba"
    family = "None"
    hacker = "None"
    hash1 = "321537007ea5052a43ffa46a6976075cee6a4902af0c98b9fd711b9f572c20fd"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "'* PAYLOAD DATA" fullword ascii
    $s2 = " = Shell(" ascii
    $s3 = "= Environ(\"USERPROFILE\")" fullword ascii
    $s4 = "'**************************************************************" fullword ascii
    $s5 = "ChDir (" fullword ascii
    $s6 = "'* MACRO CODE" fullword ascii
  condition:
    4 of them
}