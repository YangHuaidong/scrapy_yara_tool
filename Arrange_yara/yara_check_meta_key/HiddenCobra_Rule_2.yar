rule HiddenCobra_Rule_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-06-13"
    description = "Detects Hidden Cobra Malware"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/alerts/TA17-164A"
    threatname = "None"
    threattype = "None"
  strings:
    $STR1 = "Wating" wide ascii fullword
    $STR2 = "Reamin" wide ascii fullword
    $STR3 = "laptos" wide ascii fullword
  condition:
    ( uint16(0) == 0x5A4D or
    uint16(0) == 0xCFD0 or
    uint16(0) == 0xC3D4 or
    uint32(0) == 0x46445025 or
    uint32(1) == 0x6674725C
    ) and all of them
}