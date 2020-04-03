rule CN_Honker_cleaniis {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file cleaniis.exe"
    family = "None"
    hacker = "None"
    hash = "372bc64c842f6ff0d9a1aa2a2a44659d8b88cb40"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "iisantidote <logfile dir> <ip or string to hide>" fullword ascii /* PEStudio Blacklist: strings */
    $s4 = "IIS log file cleaner by Scurt" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and all of them
}