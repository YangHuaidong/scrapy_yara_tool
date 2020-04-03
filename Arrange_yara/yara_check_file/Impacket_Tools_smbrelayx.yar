rule Impacket_Tools_smbrelayx {
   meta:
      description = "Compiled Impacket Tools"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "9706eb99e48e445ac4240b5acb2efd49468a800913e70e40b25c2bf80d6be35f"
   strings:
      $s1 = "impacket.examples.secretsdump" fullword ascii
      $s2 = "impacket.examples.serviceinstall" fullword ascii
      $s3 = "impacket.smbserver(" fullword ascii
      $s4 = "SimpleHTTPServer(" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 18000KB and 3 of them )
}