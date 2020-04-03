rule CN_Honker_IIS_logcleaner1_0_readme {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Script from disclosed CN Honker Pentest Toolset - file readme.txt"
    family = "None"
    hacker = "None"
    hash = "2ab47d876b49e9a693f602f3545381415e82a556"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "LogCleaner.exe <ip> [Logpath]" fullword ascii
    $s3 = "http://l-y.vicp.net" fullword ascii
  condition:
    filesize < 7KB and all of them
}