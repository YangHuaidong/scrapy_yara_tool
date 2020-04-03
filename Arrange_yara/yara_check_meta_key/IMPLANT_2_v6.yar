rule IMPLANT_2_v6 {
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
    $STR1 = { e8 [2] ff ff 8b [0-6] 00 04 00 00 7F ?? [1-2] 00 02 00 00 7F
    ?? [1-2] 00 01 00 00 7F ?? [1-2] 80 00 00 00 7F ?? 83 ?? 40 7F}
  condition:
    (uint16(0) == 0x5A4D) and all of them
}