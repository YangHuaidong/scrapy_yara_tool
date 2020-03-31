rule Impacket_Tools_sniff {
   meta:
      description = "Compiled Impacket Tools"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "8ab2b60aadf97e921e3a9df5cf1c135fbc851cb66d09b1043eaaa1dc01b9a699"
   strings:
      $s1 = "ssniff" fullword ascii
      $s2 = "impacket.eap(" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and all of them )
}