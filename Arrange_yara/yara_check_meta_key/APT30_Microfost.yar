rule APT30_Microfost {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file 310a4a62ba3765cbf8e8bbb9f324c503"
    family = "None"
    hacker = "None"
    hash = "57169cb4b8ef7a0d7ebd7aa039d1a1efd6eb639e"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Copyright (c) 2007 Microfost All Rights Reserved" fullword wide
    $s2 = "Microfost" fullword wide
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}