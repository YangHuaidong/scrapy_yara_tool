rule Ysoserial_Payload_C3P0 {
   meta:
      description = "Ysoserial Payloads - file C3P0.bin"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/frohoff/ysoserial"
      date = "2017-02-04"
      hash1 = "9932108d65e26d309bf7d97d389bc683e52e91eb68d0b1c8adfe318a4ec6e58b"
   strings:
      $x1 = "exploitppppw" fullword ascii
   condition:
      ( uint16(0) == 0xedac and filesize < 3KB and all of them )
}