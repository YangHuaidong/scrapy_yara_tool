rule APT_CobaltStrike_Beacon_Indicator {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-11-09"
    description = "Detects CobaltStrike beacons"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://github.com/JPCERTCC/aa-tools/blob/master/cobaltstrikescan.py"
    threatname = "None"
    threattype = "None"
  strings:
    $v1 = { 73 70 72 6e 67 00 }
    $v2 = { 69 69 69 69 69 69 69 69 }
  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and all of them
}