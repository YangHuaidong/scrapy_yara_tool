rule EquationGroup_nethide_Implant {
   meta:
      description = "EquationGroup Malware - file nethide_Implant.dll"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "b2daf9058fdc5e2affd5a409aebb90343ddde4239331d3de8edabeafdb3a48fa"
   strings:
      $s1 = "\\\\.\\dlcndi" fullword ascii
      $s2 = "s\\drivers\\" fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 90KB and all of them )
}