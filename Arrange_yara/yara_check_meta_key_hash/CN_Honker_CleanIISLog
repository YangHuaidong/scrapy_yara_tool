rule CN_Honker_CleanIISLog {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file CleanIISLog.exe"
    family = "None"
    hacker = "None"
    hash = "827cd898bfe8aa7e9aaefbe949d26298f9e24094"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Usage: CleanIISLog <LogFile>|<.> <CleanIP>|<.>" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and all of them
}