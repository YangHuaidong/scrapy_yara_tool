rule Waterbear_2_Jun17 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-06-23"
    description = "Detects malware from Operation Waterbear"
    family = "None"
    hacker = "None"
    hash1 = "dcb5c350af76c590002a8ea00b01d862b4d89cccbec3908bfe92fdf25eaa6ea4"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/L9g9eR"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "downloading movie" fullword ascii
    $s2 = "name=\"test.exe\"/>" fullword ascii
    $s3 = "<description>Test Application</description>" fullword ascii
    $s4 = "UI look 2003" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}