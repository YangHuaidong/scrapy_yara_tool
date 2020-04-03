rule lnk_detect {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018/04/06"
    description = "Detects malicious LNK file from NCSC report"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
    threatname = "None"
    threattype = "None"
  strings:
    $lnk_magic = { 4c 00 00 00 01 14 02 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
    $lnk_target = { 41 00 55 00 54 00 4f 00 45 00 58 00 45 00 43 00 2e 00 42 00 41 00 54 }
    $s1 = { 5c 00 5c 00 31 00 }
    $s2 = { 5c 00 5c 00 32 00 }
    $s3 = { 5c 00 5c 00 33 00 }
    $s4 = { 5c 00 5c 00 34 00 }
    $s5 = { 5c 00 5c 00 35 00 }
    $s6 = { 5c 00 5c 00 36 00 }
    $s7 = { 5c 00 5c 00 37 00 }
    $s8 = { 5c 00 5c 00 38 00 }
    $s9 = { 5c 00 5c 00 39 00 }
  condition:
    uint32be(0) == 0x4c000000 and
    uint32be(4) == 0x01140200 and
    (($lnk_magic at 0) and $lnk_target) and 1 of ($s*)
}