rule APT30_Generic_A {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file af1c1c5d8031c4942630b6a10270d8f4"
    family = "None"
    hacker = "None"
    hash1 = "9f49aa1090fa478b9857e15695be4a89f8f3e594"
    hash2 = "396116cfb51cee090822913942f6ccf81856c2fb"
    hash3 = "fef9c3b4b35c226501f7d60816bb00331a904d5b"
    hash4 = "7c9a13f1fdd6452fb6d62067f958bfc5fec1d24e"
    hash5 = "5257ba027abe3a2cf397bfcae87b13ab9c1e9019"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s5 = "WPVWhhiA" fullword ascii
    $s6 = "VPWVhhiA" fullword ascii
    $s11 = "VPhhiA" fullword ascii
    $s12 = "uUhXiA" fullword ascii
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}