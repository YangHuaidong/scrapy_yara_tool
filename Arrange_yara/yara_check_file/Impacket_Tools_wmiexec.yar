rule Impacket_Tools_wmiexec {
   meta:
      description = "Compiled Impacket Tools"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "19544863758341fe7276c59d85f4aa17094045621ca9c98f8a9e7307c290bad4"
   strings:
      $s1 = "bwmiexec.exe.manifest" fullword ascii
      $s2 = "swmiexec" fullword ascii
      $s3 = "\\yzHPlU=QA" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and 2 of them )
}