rule CN_Honker_SwordHonkerEdition {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file SwordHonkerEdition.exe"
    family = "None"
    hacker = "None"
    hash = "3f9479151c2cada04febea45c2edcf5cece1df6c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "\\bin\\systemini\\MyPort.ini" fullword wide /* PEStudio Blacklist: strings */
    $s1 = "PortThread=200 //" fullword wide /* PEStudio Blacklist: strings */
    $s2 = " Port Open -> " fullword wide /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 375KB and all of them
}