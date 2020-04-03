rule CN_Honker_InvasionErasor {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file InvasionErasor.exe"
    family = "None"
    hacker = "None"
    hash = "b37ecd9ee6b137a29c9b9d2801473a521b168794"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "c:\\windows\\system32\\config\\*.*" fullword wide /* PEStudio Blacklist: strings */
    $s2 = "c:\\winnt\\*.txt" fullword wide /* PEStudio Blacklist: os */
    $s3 = "Command1" fullword ascii /* PEStudio Blacklist: strings */
    $s4 = "Win2003" fullword ascii /* PEStudio Blacklist: os */
    $s5 = "Win 2000" fullword ascii /* PEStudio Blacklist: os */
  condition:
    uint16(0) == 0x5a4d and filesize < 60KB and all of them
}