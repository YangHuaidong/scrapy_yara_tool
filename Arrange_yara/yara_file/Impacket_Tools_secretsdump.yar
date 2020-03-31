rule Impacket_Tools_secretsdump {
   meta:
      description = "Compiled Impacket Tools"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "47afa5fd954190df825924c55112e65fd8ed0f7e1d6fd403ede5209623534d7d"
   strings:
      $s1 = "ssecretsdump" fullword ascii
      $s2 = "impacket.ese(" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}