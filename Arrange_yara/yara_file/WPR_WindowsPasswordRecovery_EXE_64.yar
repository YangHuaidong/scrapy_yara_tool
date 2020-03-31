rule WPR_WindowsPasswordRecovery_EXE_64 {
   meta:
      description = "Windows Password Recovery - file ast64.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-03-15"
      hash1 = "4e1ea81443b34248c092b35708b9a19e43a1ecbdefe4b5180d347a6c8638d055"
   strings:
      $s1 = "%B %d %Y  -  %H:%M:%S" fullword wide
      $op0 = { 48 8d 8c 24 50 22 00 00 e8 bf eb ff ff 4c 8b c7 } /* Opcode */
      $op1 = { ff 15 16 25 01 00 f7 d8 1b } /* Opcode */
      $op2 = { e8 c2 26 00 00 83 20 00 83 c8 ff 48 8b 5c 24 30 } /* Opcode */
   condition:
      ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}