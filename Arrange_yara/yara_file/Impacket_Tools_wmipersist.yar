rule Impacket_Tools_wmipersist {
   meta:
      description = "Compiled Impacket Tools"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "2527fff1a3c780f6a757f13a8912278a417aea84295af1abfa4666572bbbf086"
   strings:
      $s1 = "swmipersist" fullword ascii
      $s2 = "\\yzHPlU=QA" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}