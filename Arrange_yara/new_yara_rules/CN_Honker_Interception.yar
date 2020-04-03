rule CN_Honker_Interception {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file Interception.exe"
    family = "None"
    hacker = "None"
    hash = "ea813aed322e210ea6ae42b73b1250408bf40e7a"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = ".\\dat\\Hookmsgina.dll" fullword ascii /* PEStudio Blacklist: strings */
    $s5 = "WinlogonHackEx " fullword wide /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 160KB and all of them
}