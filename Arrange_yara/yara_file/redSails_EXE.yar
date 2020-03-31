rule redSails_EXE {
   meta:
      description = "Detects Red Sails Hacktool by WinDivert references"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/BeetleChunks/redsails"
      date = "2017-10-02"
      hash1 = "7a7861d25b0c038d77838ecbd5ea5674650ad4f5faf7432a6f3cfeb427433fac"
   strings:
      $s1 = "bWinDivert64.dll" fullword ascii
      $s2 = "bWinDivert32.dll" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 6000KB and all of them )
}