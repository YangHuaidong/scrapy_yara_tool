rule CN_Honker_Happy_Happy {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file Happy.exe"
    family = "None"
    hacker = "None"
    hash = "92067d8dad33177b5d6c853d4d0e897f2ee846b0"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<form.*?method=\"post\"[\\s\\S]*?</form>" fullword wide /* PEStudio Blacklist: strings */
    $s2 = "domainscan.exe" fullword wide /* PEStudio Blacklist: strings */
    $s3 = "http://www.happysec.com/" fullword wide
    $s4 = "cmdshell" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 655KB and 2 of them
}