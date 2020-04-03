rule Impacket_Tools_netview {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-07"
    description = "Compiled Impacket Tools"
    family = "None"
    hacker = "None"
    hash1 = "ab909f8082c2d04f73d8be8f4c2640a5582294306dffdcc85e83a39d20c49ed6"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/maaaaz/impacket-examples-windows"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "impacket.dcerpc.v5.wkst(" fullword ascii
    $s2 = "dummy_threading(" fullword ascii
    $s3 = "snetview" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}