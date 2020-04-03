rule CN_Honker_T00ls_Lpk_Sethc_v3_LPK {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file LPK.DAT"
    family = "None"
    hacker = "None"
    hash = "cf2549bbbbdb7aaf232d9783873667e35c8d96c1"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "FreeHostKillexe.exe" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "\\sethc.exe /G everyone:F" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "c:\\1.exe" fullword ascii /* PEStudio Blacklist: strings */
    $s4 = "Set user Group Error! Username:" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 400KB and all of them
}