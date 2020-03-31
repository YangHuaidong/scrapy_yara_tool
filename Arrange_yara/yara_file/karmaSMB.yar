rule karmaSMB {
   meta:
      description = "Compiled Impacket Tools"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/maaaaz/impacket-examples-windows"
      date = "2017-04-07"
      hash1 = "d256d1e05695d62a86d9e76830fcbb856ba7bd578165a561edd43b9f7fdb18a3"
   strings:
      $s1 = "bkarmaSMB.exe.manifest" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 17000KB and all of them )
}