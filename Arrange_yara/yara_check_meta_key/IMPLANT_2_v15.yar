rule IMPLANT_2_v15 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-10"
    description = "CORESHELL/SOURFACE Implant by APT28"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $XOR_LOOP1 = { 32 1c 02 33 d2 8b c7 89 5d e4 bb 06 00 00 00 f7 f3 }
    $XOR_LOOP2 = { 32 1c 02 8b c1 33 d2 b9 06 00 00 00 f7 f1 }
    $XOR_LOOP3 = { 02 c3 30 06 8b 5d f0 8d 41 fe 83 f8 06 }
  condition:
    (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
    uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}