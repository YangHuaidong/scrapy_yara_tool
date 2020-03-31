rule Impacket_Tools_sniffer {
   meta:
      description = "Compiled Impacket Tools"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "efff15e1815fb3c156678417d6037ddf4b711a3122c9b5bc2ca8dc97165d3769"
   strings:
      $s1 = "ssniffer" fullword ascii
      $s2 = "impacket.dhcp(" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and all of them )
}