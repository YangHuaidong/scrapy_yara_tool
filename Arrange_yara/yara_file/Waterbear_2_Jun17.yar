rule Waterbear_2_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      hash1 = "dcb5c350af76c590002a8ea00b01d862b4d89cccbec3908bfe92fdf25eaa6ea4"
   strings:
      $s1 = "downloading movie" fullword ascii
      $s2 = "name=\"test.exe\"/>" fullword ascii
      $s3 = "<description>Test Application</description>" fullword ascii
      $s4 = "UI look 2003" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}