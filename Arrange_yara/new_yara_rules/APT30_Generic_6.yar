rule APT30_Generic_6 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample"
    family = "None"
    hacker = "None"
    hash0 = "b9aafb575d3d1732cb8fdca5ea226cebf86ea3c9"
    hash1 = "2c5e347083b77c9ead9e75d41e2fabe096460bba"
    hash2 = "5d39a567b50c74c4a921b5f65713f78023099933"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "GetStar" fullword
    $s1 = ".rdUaS" fullword
    $s2 = "%sOTwp/&A\\L" fullword
    $s3 = "a Encrt% Flash Disk" fullword
    $s4 = "ypeAutoRuChec" fullword
    $s5 = "NoDriveT" fullword
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}