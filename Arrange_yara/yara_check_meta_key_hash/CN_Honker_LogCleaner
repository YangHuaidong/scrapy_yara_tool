rule CN_Honker_LogCleaner {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file LogCleaner.exe"
    family = "None"
    hacker = "None"
    hash = "ab77ed5804b0394d58717c5f844d9c0da5a9f03e"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = ".exe <ip> [(path]" fullword ascii
    $s4 = "LogCleaner v" ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 250KB and all of them
}