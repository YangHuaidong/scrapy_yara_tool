rule CN_Honker_Alien_ee {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file ee.exe"
    family = "None"
    hacker = "None"
    hash = "15a7211154ee7aca29529bd5c2500e0d33d7f0b3"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "GetIIS UserName and PassWord." fullword wide /* PEStudio Blacklist: strings */
    $s2 = "Read IIS ID For FreeHost." fullword wide /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 50KB and all of them
}