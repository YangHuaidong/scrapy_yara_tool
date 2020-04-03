rule CN_Honker_Injection_transit {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file Injection_transit.exe"
    family = "None"
    hacker = "None"
    hash = "f4fef2e3d310494a3c3962a49c7c5a9ea072b2ea"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<description>Your app description here</description> " fullword ascii /* PEStudio Blacklist: strings */
    $s4 = "Copyright (C) 2003 ZYDSoft Corp." fullword wide /* PEStudio Blacklist: os */
    $s5 = "ScriptnackgBun" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 3175KB and all of them
}