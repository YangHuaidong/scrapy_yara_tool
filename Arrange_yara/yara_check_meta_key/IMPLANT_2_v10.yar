rule IMPLANT_2_v10 {
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
    $STR1 = { 83 ?? 06 [7-17] fa [0-10] 45 [2-4] 48 [2-4] e8 [2] FF FF [6-8]
    48 8d [3] 48 89 [3] 45 [2] 4? [1-2] 01}
  condition:
    (uint16(0) == 0x5A4D) and all of them
}