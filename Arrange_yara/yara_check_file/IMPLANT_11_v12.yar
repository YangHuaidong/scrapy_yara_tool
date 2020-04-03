rule IMPLANT_11_v12 {
   meta:
      description = "Mini Duke Implant by APT29"
      author = "US CERT"
      reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
      date = "2017-02-10"
      score = 85
   strings:
      $STR1 = {63 74 00 00} // ct
      $STR2 = {72 6F 74 65} // rote
      $STR3 = {75 61 6C 50} // triV
      $STR4 = {56 69 72 74} // Plau
      $STR5 = { e8 00 00 00 00 }
      $STR6 = { 64 FF 35 00 00 00 00 }
      $STR7 = {D2 C0}
      $STR8 = /\x63\x74\x00\x00.{3,20}\x72\x6F\x74\x65.{3,20}\x75\x61\x6C\x50.{3,20}\x56\x69\x72\x74/
   condition:
      (uint16(0) == 0x5A4D) and #STR5 > 4 and all of them
}