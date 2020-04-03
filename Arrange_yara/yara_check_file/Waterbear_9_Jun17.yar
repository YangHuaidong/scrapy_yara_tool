rule Waterbear_9_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      hash1 = "fc74d2434d48b316c9368d3f90fea19d76a20c09847421d1469268a32f59664c"
   strings:
      $s1 = "ADVPACK32.DLL" fullword wide
      $s2 = "ADVPACK32" fullword wide
      $a1 = "U2_Dll.dll" fullword ascii
      $b1 = "ProUpdate" fullword ascii
      $b2 = "Update.dll" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 30KB and all of ($s*) and ( $a1 or all of ($b*) )
}