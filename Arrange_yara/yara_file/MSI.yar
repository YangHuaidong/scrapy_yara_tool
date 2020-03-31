rule MSI {
   strings:
      $r1 = { 52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79 }
   condition:
      uint16(0) == 0xCFD0 and $r1
}