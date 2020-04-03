rule Suspicious_AutoIt_by_Microsoft {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-12-14"
    description = "Detects a AutoIt script with Microsoft identification"
    family = "None"
    hacker = "None"
    hash1 = "c0cbcc598d4e8b501aa0bd92115b4c68ccda0993ca0c6ce19edd2e04416b6213"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research - VT"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Microsoft Corporation. All rights reserved" fullword wide
    $s2 = "AutoIt" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and all of them
}