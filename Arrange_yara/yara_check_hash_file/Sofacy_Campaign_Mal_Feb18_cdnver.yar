rule Sofacy_Campaign_Mal_Feb18_cdnver {
  meta:
    author = Spider
    comment = None
    date = 2018-02-07
    description = Detects Sofacy malware
    family = Feb18
    hacker = None
    hash1 = 12e6642cf6413bdf5388bee663080fa299591b2ba023d069286f3be9647547c8
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = https://twitter.com/ClearskySec/status/960924755355369472
    threatname = Sofacy[Campaign]/Mal.Feb18.cdnver
    threattype = Campaign
  strings:
    $x1 = "cdnver.dll" fullword wide
    $x2 = { 25 73 0A 00 00 00 00 00 30 00 00 00 20 00 2D 00
    20 00 00 00 0A 00 00 00 25 00 73 00 00 00 00 00
    69 00 6D 00 61 00 67 00 65 00 2F 00 6A 00 70 00
    65 00 67 }
    $s1 = "S7%s - %lu" fullword ascii
    $s2 = "SNFIRNW" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 90KB and (
    pe.imphash() == "01f3d0fe6fb9d9df24620e67afc143c7" or
    1 of ($x*) or
    2 of them
}