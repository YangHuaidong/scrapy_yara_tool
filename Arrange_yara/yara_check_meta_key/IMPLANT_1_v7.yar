rule IMPLANT_1_v7 {
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
    $XOR_FUNCT = { C7 45 ?? ?? ?? 00 10 8B 0E 6A ?? FF 75 ?? E8 ?? ?? FF FF }
  condition:
    (uint16(0) == 0x5A4D) and all of them
}