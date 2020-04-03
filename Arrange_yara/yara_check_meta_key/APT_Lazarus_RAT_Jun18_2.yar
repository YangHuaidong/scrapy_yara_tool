rule APT_Lazarus_RAT_Jun18_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-06-01"
    description = "Detects Lazarus Group RAT"
    family = "None"
    hacker = "None"
    hash1 = "e6096fb512a6d32a693491f24e67d772f7103805ad407dc37065cebd1962a547"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://twitter.com/DrunkBinary/status/1002587521073721346"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\KB\\Release\\" ascii
    $s3 = "KB, Version 1.0" fullword wide
    $s4 = "TODO: (c) <Company name>.  All rights reserved." fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 5000KB and 2 of them
}