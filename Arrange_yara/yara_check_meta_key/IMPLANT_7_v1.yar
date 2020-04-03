rule IMPLANT_7_v1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-10"
    description = "Implant 7 by APT29"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $STR1 = { 8a 44 0a 03 32 c3 0f b6 c0 66 89 04 4e 41 3b cf 72 ee }
    $STR2 = { f3 0f 6f 04 08 66 0f ef c1 f3 0f 7f 04 11 83 c1 10 3b cf 72 eb }
  condition:
    (uint16(0) == 0x5A4D) and ($STR1 or $STR2)
}