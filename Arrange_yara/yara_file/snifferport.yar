rule snifferport {
   meta:
      description = "Disclosed hacktool set (old stuff) - file snifferport.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      date = "23.11.14"
      score = 60
      hash = "d14133b5eaced9b7039048d0767c544419473144"
   strings:
      $s0 = "iphlpapi.DLL" fullword ascii
      $s5 = "ystem\\CurrentCorolSet\\" fullword ascii
      $s11 = "Port.TX" fullword ascii
      $s12 = "32Next" fullword ascii
      $s13 = "V1.2 B" fullword ascii
   condition:
      all of them
}