rule Impacket_Tools_atexec {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-07"
    description = "Compiled Impacket Tools"
    family = "None"
    hacker = "None"
    hash1 = "337bd5858aba0380e16ee9a9d8f0b3f5bfc10056ced4e75901207166689fbedc"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/maaaaz/impacket-examples-windows"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "batexec.exe.manifest" fullword ascii
    $s2 = "satexec" fullword ascii
    $s3 = "impacket.dcerpc" fullword ascii
    $s4 = "# CSZq" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 15000KB and 3 of them )
}