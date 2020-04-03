rule Waterbear_7_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      hash1 = "6891aa78524e442f4dda66dff51db9798e1f92e6fefcdf21eb870b05b0293134"
   strings:
      $s1 = "Bluthmon.exe" fullword wide
      $s2 = "Motomon.exe" fullword wide
      $s3 = "%d.%s%d%d%d" fullword ascii
      $s4 = "mywishes.hlp" fullword ascii
      $s5 = "filemon.rtf" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 80KB and all of them )
}