rule CN_Honker_GetSyskey {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file GetSyskey.exe"
    family = "None"
    hacker = "None"
    hash = "17cec5e75cda434d0a1bc8cdd5aa268b42633fe9"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "GetSyskey <SYSTEM registry file> [Output system key file]" fullword ascii /* PEStudio Blacklist: strings */
    $s4 = "The system key file \"%s\" is created." fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 40KB and all of them
}