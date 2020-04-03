rule MAL_Sednit_DelphiDownloader_Apr18_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-04-24"
    description = "Detects malware from Sednit Delphi Downloader report"
    family = "None"
    hacker = "None"
    hash1 = "ecb835d03060db1ea3496ceca2d79d7c4c6c671c9907e0b0e73bf8d3371fa931"
    hash2 = "e355a327479dcc4e71a38f70450af02411125c5f101ba262e8df99f9f0fef7b6"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.welivesecurity.com/2018/04/24/sednit-update-analysis-zebrocy/"
    threatname = "None"
    threattype = "None"
  strings:
    $ = "Processor Level: " fullword ascii
    $ = "CONNECTION ERROR" fullword ascii
    $ = "FILE_EXECUTE_AND_KILL_MYSELF" ascii
    $ = "-KILL_PROCESS-" fullword ascii
    $ = "-FILE_EXECUTE-" fullword ascii
    $ = "-DOWNLOAD_ERROR-" fullword ascii
    $ = "CMD_EXECUTE" fullword ascii
    $ = "\\Interface\\Office\\{31E12FE8-937F-1E32-871D-B1C9AOEF4D4}\\" fullword ascii
    $ = "Mozilla/3.0 (compatible; Indy Library)" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and 3 of them
}