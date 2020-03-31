rule Waterbear_8_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      hash1 = "bd06f6117a0abf1442826179f6f5e1932047b4a6c14add9149e8288ab4a902c3"
      hash1 = "5dba8ddf05cb204ef320a72a0c031e55285202570d7883f2ff65135ec35b3dd0"
   strings:
      $s1 = "Update.dll" fullword ascii
      $s2 = "ADVPACK32.DLL" fullword wide
      $s3 = "\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\" fullword ascii
      $s4 = "\\drivers\\sftst.sys" fullword ascii
      $s5 = "\\\\.\\SFilter" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 40KB and all of them )
}