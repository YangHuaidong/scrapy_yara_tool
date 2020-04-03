rule CN_Honker_WebRobot {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file WebRobot.exe"
    family = "None"
    hacker = "None"
    hash = "af054994c911b4301490344fca4bb19a9f394a8f"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "%d-%02d-%02d %02d^%02d^%02d ScanReprot.htm" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "\\log\\ProgramDataFile.dat" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "\\data\\FilterKeyword.txt" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}