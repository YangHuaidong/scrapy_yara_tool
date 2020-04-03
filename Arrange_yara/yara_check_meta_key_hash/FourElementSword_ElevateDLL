rule FourElementSword_ElevateDLL {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-04-18"
    description = "Detects FourElementSword Malware"
    family = "None"
    hacker = "None"
    hash1 = "3dfc94605daf51ebd7bbccbb3a9049999f8d555db0999a6a7e6265a7e458cab9"
    hash2 = "5f3d0a319ecc875cc64a40a34d2283cb329abcf79ad02f487fbfd6bef153943c"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www.arbornetworks.com/blog/asert/four-element-sword-engagement/"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Elevate.dll" fullword wide
    $x2 = "ResN32.dll" fullword wide
    $s1 = "Kingsoft\\Antivirus" fullword wide
    $s2 = "KasperskyLab\\protected" fullword wide
    $s3 = "Sophos" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 500KB and 1 of ($x*) and all of ($s*) )
    or ( all of them )
}