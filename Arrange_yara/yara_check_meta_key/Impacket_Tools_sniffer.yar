rule Impacket_Tools_sniffer {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-07"
    description = "Compiled Impacket Tools"
    family = "None"
    hacker = "None"
    hash1 = "efff15e1815fb3c156678417d6037ddf4b711a3122c9b5bc2ca8dc97165d3769"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/maaaaz/impacket-examples-windows"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "ssniffer" fullword ascii
    $s2 = "impacket.dhcp(" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 15000KB and all of them )
}