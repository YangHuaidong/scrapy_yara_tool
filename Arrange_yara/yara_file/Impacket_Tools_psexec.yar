rule Impacket_Tools_psexec {
   meta:
      description = "Compiled Impacket Tools"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "27bb10569a872367ba1cfca3cf1c9b428422c82af7ab4c2728f501406461c364"
   strings:
      $s1 = "impacket.examples.serviceinstall(" fullword ascii
      $s2 = "spsexec" fullword ascii
      $s3 = "impacket.examples.remcomsvc(" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and 2 of them )
}