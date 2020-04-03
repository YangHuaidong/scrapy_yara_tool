rule APT_FIN7_EXE_Sample_Aug18_8 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-08-01"
    description = "Detects sample from FIN7 report in August 2018"
    family = "None"
    hacker = "None"
    hash1 = "d8bda53d7f2f1e4e442a0e1c30a20d6b0ac9c6880947f5dd36f78e4378b20c5c"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "GetL3st3rr" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 600KB and all of them
}