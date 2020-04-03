rule Waterbear_10_Jun17 {
   meta:
      description = "Detects malware from Operation Waterbear"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/L9g9eR"
      date = "2017-06-23"
      hash1 = "3b1e67e0e86d912d7bc6dee5b0f801260350e8ce831c93c3e9cfe5a39e766f41"
   strings:
      $s1 = "ADVPACK32.DLL" fullword wide
      $s5 = "ADVPACK32" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 30KB and all of them )
}