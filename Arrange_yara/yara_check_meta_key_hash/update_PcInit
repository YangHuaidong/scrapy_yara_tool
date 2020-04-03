rule update_PcInit {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file PcInit.exe"
    family = "None"
    hacker = "None"
    hash = "a6facc4453f8cd81b8c18b3b3004fa4d8e2f5344"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\svchost.exe" fullword ascii
    $s2 = "%s%08x.001" fullword ascii
    $s3 = "Global\\ps%08x" fullword ascii
    $s4 = "drivers\\" fullword ascii /* Goodware String - occured 2 times */
    $s5 = "StrStrA" fullword ascii /* Goodware String - occured 43 times */
    $s6 = "StrToIntA" fullword ascii /* Goodware String - occured 44 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 50KB and all of them
}