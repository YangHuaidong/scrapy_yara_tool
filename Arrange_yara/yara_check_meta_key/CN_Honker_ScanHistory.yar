rule CN_Honker_ScanHistory {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file ScanHistory.exe"
    family = "None"
    hacker = "None"
    hash = "14c31e238924ba3abc007dc5a3168b64d7b7de8d"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "ScanHistory.exe" fullword wide /* PEStudio Blacklist: strings */
    $s2 = ".\\Report.dat" fullword wide /* PEStudio Blacklist: strings */
    $s3 = "select  * from  Results order by scandate desc" fullword wide /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and all of them
}