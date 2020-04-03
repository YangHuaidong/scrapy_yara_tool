rule Armitage_msfconsole {
   meta:
      description = "Detects Armitage component"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-12-24"
      hash1 = "662ba75c7ed5ac55a898f480ed2555d47d127a2d96424324b02724b3b2c95b6a"
   strings:
      $s1 = "\\umeterpreter\\u >" fullword ascii
      $s3 = "^meterpreter >" fullword ascii
      $s11 = "\\umsf\\u>" fullword ascii
   condition:
      ( uint16(0) == 0x6d5e and
        filesize < 1KB and
        ( 8 of them )
      ) or ( all of them )
}