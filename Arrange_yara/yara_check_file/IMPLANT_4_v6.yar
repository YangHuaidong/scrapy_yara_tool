rule IMPLANT_4_v6 {
   meta:
      description = "BlackEnergy / Voodoo Bear Implant by APT28"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = "DispatchCommand" wide ascii
      $STR2 = "DispatchEvent" wide ascii
   condition:
      (uint16(0) == 0x5A4D or uint16(0) == 0xCFD0 or uint16(0) == 0xC3D4 or
      uint32(0) == 0x46445025 or uint32(1) == 0x6674725C) and all of them
}