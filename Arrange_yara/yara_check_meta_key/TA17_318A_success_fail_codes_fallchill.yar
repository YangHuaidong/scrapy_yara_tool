rule TA17_318A_success_fail_codes_fallchill {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-11-15"
    description = "HiddenCobra FallChill - success_fail_codes"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/alerts/TA17-318B"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = { 68 7a 34 12 00 }
    $s1 = { ba 7a 34 12 00 }
    $f0 = { 68 5c 34 12 00 }
    $f1 = { ba 5c 34 12 00 }
  condition:
    (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and (($s0 and $f0) or ($s1 and $f1))
}