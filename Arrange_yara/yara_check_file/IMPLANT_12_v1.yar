rule IMPLANT_12_v1 {
   meta:
      description = "Cosmic Duke Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $FUNC = {A1 [3-5] 33 C5 89 [2-3] 56 57 83 [4-6] 64}
   condition:
      (uint16(0) == 0x5A4D) and $FUNC
}