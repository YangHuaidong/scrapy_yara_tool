rule CN_Honker_exp_win2003 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file win2003.exe"
    family = "None"
    hacker = "None"
    hash = "47164c8efe65d7d924753fadf6cdfb897a1c03db"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Usage:system_exp.exe \"cmd\"" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "The shell \"cmd\" success!" fullword ascii /* PEStudio Blacklist: strings */
    $s4 = "Not Windows NT family OS." fullword ascii /* PEStudio Blacklist: os */
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and all of them
}