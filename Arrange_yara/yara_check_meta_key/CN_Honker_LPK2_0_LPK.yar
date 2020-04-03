rule CN_Honker_LPK2_0_LPK {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file LPK.DAT"
    family = "None"
    hacker = "None"
    hash = "5a1226e73daba516c889328f295e728f07fdf1c3"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\sethc.exe /G everyone:F" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "net1 user guest guest123!@#" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "\\dllcache\\sethc.exe" fullword ascii
    $s4 = "sathc.exe 211" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 1030KB and all of them
}