rule CN_Honker_GetHashes {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file GetHashes.exe"
    family = "None"
    hacker = "None"
    hash = "dc8bcebf565ffffda0df24a77e28af681227b7fe"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "SAM\\Domains\\Account\\Users\\Names registry hive reading error!" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "GetHashes <SAM registry file> [System key file]" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "Note: Windows registry file shall begin from 'regf' signature!" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 87KB and 2 of them
}