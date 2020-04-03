import "pe"
rule HiddenCobra_FallChill_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-11-15"
    description = "Auto-generated rule - file a606716355035d4a1ea0b15f3bee30aad41a2c32df28c2d468eafd18361d60d6"
    family = "None"
    hacker = "None"
    hash1 = "a606716355035d4a1ea0b15f3bee30aad41a2c32df28c2d468eafd18361d60d6"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.us-cert.gov/ncas/alerts/TA17-318A"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "REGSVR32.EXE.MUI" fullword wide
    $s2 = "Microsoft Corporation. All rights reserved." fullword wide
    $s3 = "c%sd.e%sc %s > \"%s\" 2>&1" fullword wide
    $s4 = "\" goto Loop" fullword ascii
    $e1 = "xolhvhlxpvg" fullword ascii
    $e2 = "tvgslhgybmanv" fullword ascii
    $e3 = "CivagvTllosvok32Smakhslg" fullword ascii
    $e4 = "GvgCfiivmgDrivxglibW" fullword ascii
    $e5 = "OkvmPilxvhhTlpvm" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and (
    pe.imphash() == "6135d9bc3591ae7bc72d070eadd31755" or
    3 of ($s*) or
    4 of them
}