rule Lazarus_Dec_17_2 {
   meta:
      description = "Detects Lazarus malware from incident in Dec 2017"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/8U6fY2"
      date = "2017-12-20"
      hash1 = "cbebafb2f4d77967ffb1a74aac09633b5af616046f31dddf899019ba78a55411"
      hash2 = "9ca3e56dcb2d1b92e88a0d09d8cab2207ee6d1f55bada744ef81e8b8cf155453"
   strings:
      $s1 = "SkypeSetup.exe" fullword wide
      $s2 = "%s\\SkypeSetup.exe" fullword ascii
      $s3 = "Skype Technologies S.A." fullword wide
      $a1 = "Microsoft Code Signing PCA" ascii wide
   condition:
      uint16(0) == 0x5a4d and filesize < 7000KB and (
        all of ($s*) and not $a1
      )
}