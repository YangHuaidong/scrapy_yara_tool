rule Impacket_Tools_smbrelayx {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-07"
    description = "Compiled Impacket Tools"
    family = "None"
    hacker = "None"
    hash1 = "9706eb99e48e445ac4240b5acb2efd49468a800913e70e40b25c2bf80d6be35f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/maaaaz/impacket-examples-windows"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "impacket.examples.secretsdump" fullword ascii
    $s2 = "impacket.examples.serviceinstall" fullword ascii
    $s3 = "impacket.smbserver(" fullword ascii
    $s4 = "SimpleHTTPServer(" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 18000KB and 3 of them )
}