rule EquationGroup_Toolset_Apr17_RemoteCommand_Lp {
   meta:
      description = "Detects EquationGroup Tool - April Leak"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
      date = "2017-04-15"
      hash1 = "57b47613a3b5dd820dae59fc6dc2b76656bd578f015f367675219eb842098846"
   strings:
      $s1 = "Failure parsing command from %hs:%u: os=%u plugin=%u" fullword wide
      $s2 = "Unable to get TCP listen port: %08x" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}