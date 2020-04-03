import "pe"
rule DragonFly_APT_Sep17_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-09-12"
    description = "Detects malware from DrqgonFly APT report"
    family = "None"
    hacker = "None"
    hash1 = "b051a5997267a5d7fa8316005124f3506574807ab2b25b037086e2e971564291"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "kernel64.dll" fullword ascii
    $s2 = "ws2_32.dQH" fullword ascii
    $s3 = "HGFEDCBADCBA" fullword ascii
    $s4 = "AWAVAUATWVSU" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and
    filesize < 40KB and (
    pe.imphash() == "6f03fb864ff388bac8680ac5303584be" or
    all of them
}