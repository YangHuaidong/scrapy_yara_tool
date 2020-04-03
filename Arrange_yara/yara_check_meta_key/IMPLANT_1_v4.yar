rule IMPLANT_1_v4 {
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
    $XOR_LOOP = { 8B 45 FC 8D 0C 06 33 D2 6A 0B 8B C6 5B F7 F3 8A 82 ?? ??
    ?? ?? 32 04 0F 46 88 01 3B 75 0C 7C E0 }
  condition:
    (uint16(0) == 0x5A4D) and all of them
}