rule IMPLANT_1_v1 {
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
    $STR1 = {6A ?? E8 ?? ?? FF FF 59 85 C0 74 0B 8B C8 E8 ?? ?? FF FF 8B F0
    EB 02 33 F6 8B CE E8 ?? ?? FF FF 85 F6 74 0E 8B CE E8 ?? ?? FF FF 56
    E8 ?? ?? FF FF 59}
  condition:
    (uint16(0) == 0x5A4D) and all of them
}