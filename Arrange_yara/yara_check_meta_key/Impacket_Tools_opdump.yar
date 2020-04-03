rule Impacket_Tools_opdump {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-07"
    description = "Compiled Impacket Tools"
    family = "None"
    hacker = "None"
    hash1 = "e2205539f29972d4e2a83eabf92af18dd406c9be97f70661c336ddf5eb496742"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/maaaaz/impacket-examples-windows"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "bopdump.exe.manifest" fullword ascii
    $s3 = "sopdump" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}