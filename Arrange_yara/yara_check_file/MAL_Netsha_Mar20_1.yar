rule MAL_Netsha_Mar20_1 {
   meta:
      description = "Detects Netsha malware"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2020-03-24"
      hash1 = "27c67eb1378c2fd054c6649f92ec8ee9bfcb6f790224036c974f6c883c46f586"
   strings:
      $x1 = "the best. Fuck off all the rest."
      $x2 = "Neshta 1.0 Made in Belarus. " ascii
      $op1 = { 85 c0 93 0f 85 62 ff ff ff 5e 5b 89 ec 5d c2 04 }
      $op2 = { e8 e5 f1 ff ff 8b c3 e8 c6 ff ff ff 85 c0 75 0c }
      $op3 = { eb 02 33 db 8b c3 5b c3 53 85 c0 74 15 ff 15 34 }
   condition:
      uint16(0) == 0x5a4d and
      filesize < 3000KB and
      1 of ($x*) or 3 of them
}