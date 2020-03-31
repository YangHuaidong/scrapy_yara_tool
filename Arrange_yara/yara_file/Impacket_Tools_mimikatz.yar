rule Impacket_Tools_mimikatz {
   meta:
      description = "Compiled Impacket Tools"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "2d8d500bcb3ffd22ddd8bd68b5b2ce935c958304f03729442a20a28b2c0328c1"
   strings:
      $s1 = "impacket" fullword ascii
      $s2 = "smimikatz" fullword ascii
      $s3 = "otwsdlc" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}