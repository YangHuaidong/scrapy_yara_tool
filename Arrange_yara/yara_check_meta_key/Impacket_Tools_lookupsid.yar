rule Impacket_Tools_lookupsid {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-07"
    description = "Compiled Impacket Tools"
    family = "None"
    hacker = "None"
    hash1 = "47756725d7a752d3d3cfccfb02e7df4fa0769b72e008ae5c85c018be4cf35cc1"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/maaaaz/impacket-examples-windows"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "slookupsid" fullword ascii
    $s2 = "impacket.dcerpc" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 15000KB and all of them )
}