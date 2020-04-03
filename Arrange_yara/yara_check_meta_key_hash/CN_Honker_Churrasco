rule CN_Honker_Churrasco {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file Churrasco.exe"
    family = "None"
    hacker = "None"
    hash = "5a3c935d82a5ff0546eff51bb2ef21c88198f5b8"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "HEAD9 /" ascii
    $s1 = "logic_er" fullword ascii
    $s6 = "proggam" fullword ascii
    $s16 = "DtcGetTransactionManagerExA" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 12 times */
    $s17 = "GetUserNameA" fullword ascii /* PEStudio Blacklist: strings */ /* Goodware String - occured 305 times */
    $s18 = "OLEAUT" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 1276KB and all of them
}