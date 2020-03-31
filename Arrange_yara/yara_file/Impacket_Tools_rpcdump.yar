rule Impacket_Tools_rpcdump {
   meta:
      description = "Compiled Impacket Tools"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "21d85b36197db47b94b0f4995d07b040a0455ebbe6d413bc33d926ee4e0315d9"
   strings:
      $s1 = "srpcdump" fullword ascii
      $s2 = "impacket.dcerpc.v5.epm(" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}