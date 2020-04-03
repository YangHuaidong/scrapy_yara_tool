rule CN_Honker_SwordCollEdition {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file SwordCollEdition.exe"
    family = "None"
    hacker = "None"
    hash = "6e14f21cac6e2aa7535e45d81e8d1f6913fd6e8b"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "YuJianScan.exe" fullword wide /* PEStudio Blacklist: strings */
    $s1 = "YuJianScan" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 225KB and all of them
}