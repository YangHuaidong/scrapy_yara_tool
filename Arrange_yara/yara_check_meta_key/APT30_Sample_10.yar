rule APT30_Sample_10 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file 8c713117af4ca6bbd69292a78069e75b"
    family = "None"
    hacker = "None"
    hash = "eb518cda3c4f4e6938aaaee07f1f7db8ee91c901"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Version 4.7.3001" fullword wide
    $s1 = "Copyright (c) Microsoft Corporation 2004" fullword wide
    $s2 = "Microsoft(R) is a registered trademark of Microsoft Corporation in the U" wide
    $s3 = "!! Use Connect Method !!" fullword ascii
    $s4 = "(Prxy%c-%s:%u)" fullword ascii
    $s5 = "msmsgs" fullword wide
    $s18 = "(Prxy-No)" fullword ascii
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}