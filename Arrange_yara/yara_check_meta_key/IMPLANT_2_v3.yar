rule IMPLANT_2_v3 {
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
    $STR1 = {C1 EB 07 8D ?? 01 32 1C ?? 33 D2 }
    $STR2 = {2B ?? 83 ?? 06 0F 83 ?? 00 00 00 EB 02 33 }
    $STR3 = {89 ?? ?? 89 ?? ?? 89 55 ?? 89 45 ?? 3B ?? 0F 83 ?? 00 00 00 8D
    ?? ?? 8D ?? ?? FE }
  condition:
    (uint16(0) == 0x5A4D) and any of them
}