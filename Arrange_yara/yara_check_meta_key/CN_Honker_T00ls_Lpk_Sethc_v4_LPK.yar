rule CN_Honker_T00ls_Lpk_Sethc_v4_LPK {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file LPK.DAT"
    family = "None"
    hacker = "None"
    hash = "2b2ab50753006f62965bba83460e3960ca7e1926"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "http://127.0.0.1/1.exe" fullword wide /* PEStudio Blacklist: strings */
    $s2 = "FreeHostKillexe.exe" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "\\sethc.exe /G everyone:F" fullword ascii /* PEStudio Blacklist: strings */
    $s4 = "c:\\1.exe" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and 1 of them
}