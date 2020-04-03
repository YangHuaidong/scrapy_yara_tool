rule APT30_Generic_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample"
    family = "None"
    hacker = "None"
    hash0 = "b90ac3e58ed472829e2562023e6e892d2d61ac44"
    hash1 = "342036ace2e9e6d504b0dec6399e4fa92de46c12"
    hash2 = "5cdf397dfd9eb66ff5ff636777f6982c1254a37a"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Acrobat.exe" fullword wide
    $s14 = "********************************" fullword
    $s16 = "FFFF:>>>>>>>>>>>>>>>>>@" fullword
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}