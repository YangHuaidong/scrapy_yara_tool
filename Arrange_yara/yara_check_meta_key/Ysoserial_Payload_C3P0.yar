rule Ysoserial_Payload_C3P0 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-04"
    description = "Ysoserial Payloads - file C3P0.bin"
    family = "None"
    hacker = "None"
    hash1 = "9932108d65e26d309bf7d97d389bc683e52e91eb68d0b1c8adfe318a4ec6e58b"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/frohoff/ysoserial"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "exploitppppw" fullword ascii
  condition:
    ( uint16(0) == 0xedac and filesize < 3KB and all of them )
}