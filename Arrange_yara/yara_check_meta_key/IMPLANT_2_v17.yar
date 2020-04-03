rule IMPLANT_2_v17 {
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
    $STR1 = { 24 10 8b 44 24 1c 89 44 24 14 8b 44 24 24 68 36 }
    $STR2 = { 51 8d 4d dc 51 6a 01 8b d0 8b 4d e4 e8 36 04 00 }
    $STR3 = { e4 81 78 06 15 91 df 75 74 04 33 f6 eb 1a 8b 48 }
    $STR4 = { 33 d2 f7 75 f8 8b 45 d4 02 d9 03 c6 41 32 1c 3a }
    $STR5 = { 00 6a 00 56 ff d0 83 f8 ff 74 64 6a 00 8d 45 f8 }
  condition:
    (uint16(0) == 0x5A4D) and 2 of them
}