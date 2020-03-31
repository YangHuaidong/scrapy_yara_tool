rule Impacket_Tools_smbtorture {
   meta:
      description = "Compiled Impacket Tools"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "d2856e98011541883e5b335cb46b713b1a6b2c414966a9de122ee7fb226aa7f7"
   strings:
      $s1 = "impacket" fullword ascii
      $s2 = "ssmbtorture" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}