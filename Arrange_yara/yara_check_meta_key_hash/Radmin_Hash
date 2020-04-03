rule Radmin_Hash {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file Radmin_Hash.exe"
    family = "None"
    hacker = "None"
    hash = "be407bd5bf5bcd51d38d1308e17a1731cd52f66b"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<description>IEBars</description>" fullword ascii
    $s2 = "PECompact2" fullword ascii
    $s3 = "Radmin, Remote Administrator" fullword wide
    $s4 = "Radmin 3.0 Hash " fullword wide
    $s5 = "HASH1.0" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 600KB and all of them
}