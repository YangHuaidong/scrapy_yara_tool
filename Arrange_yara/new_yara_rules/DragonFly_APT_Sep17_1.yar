rule DragonFly_APT_Sep17_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-09-12"
    description = "Detects malware from DrqgonFly APT report"
    family = "None"
    hacker = "None"
    hash1 = "fc54d8afd2ce5cb6cc53c46783bf91d0dd19de604308d536827320826bc36ed9"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.symantec.com/connect/blogs/dragonfly-western-energy-sector-targeted-sophisticated-attack-group"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\Update\\Temp\\ufiles.txt" fullword wide
    $s2 = "%02d.%02d.%04d %02d:%02d" fullword wide
    $s3 = "*pass*.*" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}