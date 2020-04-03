rule IMPLANT_1_v6 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-10"
    description = "Downrage Implant by APT28"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $XORopcodes_eax = { 35 (22 07 15 0e|56 d7 a7 0a) }
    $XORopcodes_others = { 81 (F1|F2|F3|F4|F5|F6|F7) (22 07 15 0E|56 D7 A7 0A) }
  condition:
    (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
    uint32(0) == 0x46445025) and any of them
}