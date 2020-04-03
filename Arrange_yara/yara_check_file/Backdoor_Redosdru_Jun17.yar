rule Backdoor_Redosdru_Jun17 {
   meta:
      description = "Detects malware Redosdru - file systemHome.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://goo.gl/OOB3mH"
      date = "2017-06-04"
      hash1 = "4f49e17b457ef202ab0be905691ef2b2d2b0a086a7caddd1e70dd45e5ed3b309"
   strings:
      $x1 = "%s\\%d.gho" fullword ascii
      $x2 = "%s\\nt%s.dll" fullword ascii
      $x3 = "baijinUPdate" fullword ascii
      $s1 = "RegQueryValueEx(Svchost\\netsvcs)" fullword ascii
      $s2 = "serviceone" fullword ascii
      $s3 = "#p #p #p #p #p #p #p #p #p #p #p #p #p #p #p #p #p #p #p #p #p #p #p #p #f #" fullword ascii
      $s4 = "servicetwo" fullword ascii
      $s5 = "UpdateCrc" fullword ascii
      $s6 = "#[ #x #x #x #x #x #x #x #x #x #x #x #x #x #x #x #x #x #x #x #x #" fullword ascii
      $s7 = "nwsaPAgEnT" fullword ascii
      $s8 = "%-24s %-15s 0x%x(%d) " fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 700KB and 1 of ($x*) or 4 of them )
}