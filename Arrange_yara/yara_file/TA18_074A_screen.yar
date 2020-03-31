rule TA18_074A_screen {
   meta:
      description = "Detects malware mentioned in TA18-074A"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/alerts/TA18-074A"
      date = "2018-03-16"
      hash1 = "2f159b71183a69928ba8f26b76772ec504aefeac71021b012bd006162e133731"
   strings:
      $s1 = "screen.exe" fullword wide
      $s2 = "PlatformInvokeUSER32" fullword ascii
      $s3 = "GetDesktopImageF" fullword ascii
      $s4 = "PlatformInvokeGDI32" fullword ascii
      $s5 = "Too many arguments, going to store in current dir" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 60KB and 3 of them
}