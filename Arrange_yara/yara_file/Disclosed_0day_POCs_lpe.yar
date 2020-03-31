rule Disclosed_0day_POCs_lpe {
   meta:
      description = "Detects POC code from disclosed 0day hacktool set"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Disclosed 0day Repos"
      date = "2017-07-07"
      hash1 = "e10ee278f4c86d6ee1bd93a7ed71d4d59c0279381b00eb6153aedfb3a679c0b5"
      hash2 = "a5916cefa0f50622a30c800e7f21df481d7a3e1e12083fef734296a22714d088"
      hash3 = "5b701a5b5bbef7027711071cef2755e57984bfdff569fe99efec14a552d8ee43"
   strings:
      $x1 = "msiexec /f c:\\users\\%username%\\downloads\\" fullword ascii
      $x2 = "c:\\users\\%username%\\downloads\\bat.bat" fullword ascii
      $x3 = "\\payload.msi /quiet" ascii
      $x4 = "\\payload2\\WindowsTrustedRTProxy.sys" fullword wide
      $x5 = "\\payload2" fullword wide
      $x6 = "\\payload" fullword wide
      $x7 = "WindowsTrustedRTProxy.sys /grant:r administrators:RX" ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 70KB and 1 of them )
}