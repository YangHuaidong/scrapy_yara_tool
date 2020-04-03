rule IMPLANT_10_v1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-10"
    description = "CozyDuke / CozyCar / CozyBear Implant by APT29"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $STR1 = {33 ?? 83 F2 ?? 81 E2 FF 00 00 00}
    $STR2 = {0F BE 14 01 33 D0 ?? F2 [1-4] 81 E2 FF 00 00 00 66 89 [6] 40 83
    F8 ?? 72}
  condition:
    uint16(0) == 0x5A4D and ($STR1 or $STR2)
}