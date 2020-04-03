rule CN_Honker_Oracle_v1_0_Oracle {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file Oracle.exe"
    family = "None"
    hacker = "None"
    hash = "0264f4efdba09eaf1e681220ba96de8498ab3580"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "!http://localhost/index.asp?id=zhr" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "OnGetPassword" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "Mozilla/3.0 (compatible; Indy Library)" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 3455KB and all of them
}