rule EXP_DriveCrypt_1 {
   meta:
      description = "Detects DriveCrypt exploit"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2018-08-21"
      hash1 = "0dd09bc97c768abb84d0fb6d1ae7d789f1f83bfb2ce93ff9ff3c538dc1effa33"
   strings:
      $s1 = "x64passldr.exe" fullword ascii
      $s2 = "DCR.sys" fullword ascii
      $s3 = "amd64\\x64pass.sys" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 700KB and 2 of them
}