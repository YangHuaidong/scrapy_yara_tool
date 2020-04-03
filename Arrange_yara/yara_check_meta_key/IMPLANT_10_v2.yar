rule IMPLANT_10_v2 {
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
    $xor = { 34 ?? 66 33 C1 48 FF C1 }
    $nop = { 66 66 66 66 66 66 0f 1f 84 00 00 00 00 00 }
  condition:
    uint16(0) == 0x5A4D and $xor and $nop
}