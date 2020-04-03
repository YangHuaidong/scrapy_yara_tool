rule APT30_Generic_H {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file db3e5c2f2ce07c2d3fa38d6fc1ceb854"
    family = "None"
    hacker = "None"
    hash1 = "2a4c8752f3e7fde0139421b8d5713b29c720685d"
    hash2 = "4350e906d590dca5fcc90ed3215467524e0a4e3d"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "\\Temp1020.txt" fullword ascii
    $s1 = "Xmd.Txe" fullword ascii
    $s2 = "\\Internet Exp1orer" fullword ascii
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}