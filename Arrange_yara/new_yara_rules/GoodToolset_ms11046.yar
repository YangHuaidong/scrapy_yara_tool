rule GoodToolset_ms11046 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file ms11046.exe"
    family = "None"
    hacker = "None"
    hash = "f8414a374011fd239a6c6d9c6ca5851cd8936409"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "[*] Token system command" fullword ascii
    $s2 = "[*] command add user 90sec 90sec" fullword ascii
    $s3 = "[*] Add to Administrators success" fullword ascii
    $s4 = "[*] User has been successfully added" fullword ascii
    $s5 = "Program: %s%s%s%s%s%s%s%s%s%s%s" fullword ascii  /* Goodware String - occured 3 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 840KB and 2 of them
}