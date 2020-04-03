rule IMPLANT_10_v1 {
   meta:
      description = "CozyDuke / CozyCar / CozyBear Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {33 ?? 83 F2 ?? 81 E2 FF 00 00 00}
      $STR2 = {0F BE 14 01 33 D0 ?? F2 [1-4] 81 E2 FF 00 00 00 66 89 [6] 40 83
         F8 ?? 72}
   condition:
      uint16(0) == 0x5A4D and ($STR1 or $STR2)
}