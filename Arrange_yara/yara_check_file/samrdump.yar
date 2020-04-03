rule samrdump {
   meta:
      description = "Compiled Impacket Tools"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "4c2921702d18e0874b57638433474e54719ee6dfa39d323839d216952c5c834a"
   strings:
      $s2 = "bsamrdump.exe.manifest" fullword ascii
      $s3 = "ssamrdump" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}