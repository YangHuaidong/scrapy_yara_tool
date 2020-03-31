rule Kriskynote_Mar17_2 {
   meta:
      description = "Detects Kriskynote Malware"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-03"
      hash1 = "cb9a2f77868b28d98e4f9c1b27b7242fec2f2abbc91bfc21fe0573e472c5dfcb"
   strings:
      $s1 = "fgjfcn8456fgjhfg89653wetwts" fullword ascii
      $op0 = { 33 c0 80 34 30 03 40 3d e6 21 00 00 72 f4 b8 e6 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 600KB and 1 of them )
}