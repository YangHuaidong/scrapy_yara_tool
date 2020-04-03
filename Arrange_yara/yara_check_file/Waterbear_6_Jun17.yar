rule Waterbear_6_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      hash1 = "409cd490feb40d08eb33808b78d52c00e1722eee163b60635df6c6fe2c43c230"
   strings:
      $s1 = "svcdll.dll" fullword ascii
      $s2 = "log.log" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 60KB and all of them )
}