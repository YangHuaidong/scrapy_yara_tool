rule IMPLANT_9_v1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-10"
    description = "Onion Duke Implant by APT29"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
    score = 85
    threatname = "None"
    threattype = "None"
  strings:
    $STR1 = { 8b 03 8a 54 01 03 32 55 ff 41 88 54 39 ff 3b ce 72 ee }
    $STR2 = { 8B C8 83 E1 03 8A 54 19 08 8B 4D 08 32 54 01 04 40 88 54 38 FF
    3B C6 72 E7 }
    $STR3 = { 8B 55 F8 8B C8 83 E1 03 8A 4C 11 08 8B 55 FC 32 0C 10 8B 17 88
    4C 02 04 40 3B 06 72 E3 }
  condition:
    (uint16(0) == 0x5A4D or uint16(0)) and all of them
}