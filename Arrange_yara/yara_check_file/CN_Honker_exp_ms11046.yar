rule CN_Honker_exp_ms11046 {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Sample from CN Honker Pentest Toolset - file ms11046.exe
    family = ms11046
    hacker = None
    hash = f8414a374011fd239a6c6d9c6ca5851cd8936409
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/exp.ms11046
    threattype = Honker
  strings:
    $s0 = "[*] Token system command" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "[*] command add user 90sec 90sec" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "[*] Add to Administrators success" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "Program: %s%s%s%s%s%s%s%s%s%s%s" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 3 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and all of them
}