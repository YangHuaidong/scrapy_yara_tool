rule IMPLANT_6_v2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-10"
    description = "Sednit / EVILTOSS Implant by APT28"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $obf_func = { 8b 45 f8 6a 07 03 c7 33 d2 89 45 e8 8d 47 01 5b 02 4d 0f f7 f3 6a 07 8a 04 32 33 d2 f6 e9 8a c8 8b c7 f7 f3 8a 44 3e fe 02 45 fc 02 0c 32 b2 03 f6 ea 8a d8 8d 47 ff 33 d2 5f f7 f7 02 5d 14 8b 45 e8 8b 7d f4 c0 e3 06 02 1c 32 32 cb 30 08 8b 4d 14 41 47 83 ff 09 89 4d 14 89 7d f4 72 a1 }
  condition:
    (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
    uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}