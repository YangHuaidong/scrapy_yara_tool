rule APT30_Generic_I {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file fe211c7a081c1dac46e3935f7c614549"
    family = "None"
    hacker = "None"
    hash1 = "fe211c7a081c1dac46e3935f7c614549"
    hash2 = "8c9db773d387bf9b3f2b6a532e4c937c"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Copyright 2012 Google Inc. All rights reserved." fullword wide
    $s1 = "(Prxy%c-%s:%u)" fullword ascii
    $s2 = "Google Inc." fullword wide
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}