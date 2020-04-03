rule CheshireCat_Sample2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-08-08"
    description = "Auto-generated rule - file dc18850d065ff6a8364421a9c8f9dd5fcce6c7567f4881466cee00e5cd0c7aa8"
    family = "None"
    hacker = "None"
    hash = "dc18850d065ff6a8364421a9c8f9dd5fcce6c7567f4881466cee00e5cd0c7aa8"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://malware-research.org/prepare-father-of-stuxnet-news-are-coming/"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "mpgvwr32.dll" fullword ascii
    $s1 = "Unexpected failure of wait! (%d)" fullword ascii
    $s2 = "\"%s\" /e%d /p%s" fullword ascii
    $s4 = "error in params!" fullword ascii
    $s5 = "sscanf" fullword ascii
    $s6 = "<>Param : 0x%x" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and 4 of ($s*)
}