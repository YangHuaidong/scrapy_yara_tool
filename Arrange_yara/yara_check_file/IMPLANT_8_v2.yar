rule IMPLANT_8_v2 {
   meta:
      description = "HAMMERTOSS / HammerDuke Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $DOTNET= "mscorlib" ascii
      $XOR = {61 20 AA 00 00 00 61}
   condition:
      (uint16(0) == 0x5A4D) and all of them
}