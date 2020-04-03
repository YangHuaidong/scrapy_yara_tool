rule ce_enfal_cmstar_debug_msg {
  meta:
    author = "Spider"
    comment = "None"
    date = "5/10/2015"
    description = "Detects the static debug strings within CMSTAR"
    family = "None"
    hacker = "None"
    hash = "9b9cc7e2a2481b0472721e6b87f1eba4faf2d419d1e2c115a91ab7e7e6fc7f7c"
    judge = "black"
    reference = "http://goo.gl/JucrP9"
    threatname = "None"
    threattype = "None"
  strings:
    $d1 = "EEE\x0d\x0a" fullword
    $d2 = "TKE\x0d\x0a" fullword
    $d3 = "VPE\x0d\x0a" fullword
    $d4 = "VPS\x0d\x0a" fullword
    $d5 = "WFSE\x0d\x0a" fullword
    $d6 = "WFSS\x0d\x0a" fullword
    $d7 = "CM**\x0d\x0a" fullword
  condition:
    uint16(0) == 0x5a4d and all of ($d*)
}