rule CN_Honker_windows_exp {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file exp.exe"
    family = "None"
    hacker = "None"
    hash = "04334c396b165db6e18e9b76094991d681e6c993"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "c:\\windows\\system32\\command.com /c " fullword ascii /* PEStudio Blacklist: strings */
    $s8 = "OH,Sry.Too long command." fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 220KB and all of them
}