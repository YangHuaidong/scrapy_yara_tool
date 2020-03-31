rule Impacket_Tools_lookupsid {
   meta:
      description = "Compiled Impacket Tools"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "47756725d7a752d3d3cfccfb02e7df4fa0769b72e008ae5c85c018be4cf35cc1"
   strings:
      $s1 = "slookupsid" fullword ascii
      $s2 = "impacket.dcerpc" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 15000KB and all of them )
}