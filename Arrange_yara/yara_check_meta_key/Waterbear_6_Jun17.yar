rule Waterbear_6_Jun17 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-06-23"
    description = "Detects malware from Operation Waterbear"
    family = "None"
    hacker = "None"
    hash1 = "409cd490feb40d08eb33808b78d52c00e1722eee163b60635df6c6fe2c43c230"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/L9g9eR"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "svcdll.dll" fullword ascii
    $s2 = "log.log" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 60KB and all of them )
}