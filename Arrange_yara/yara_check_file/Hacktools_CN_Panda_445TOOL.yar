rule Hacktools_CN_Panda_445TOOL {
   meta:
      description = "Disclosed hacktool set - file 445TOOL.rar"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      date = "17.11.14"
      score = 60
      hash = "92050ba43029f914696289598cf3b18e34457a11"
   strings:
      $s0 = "scan.bat" fullword ascii
      $s1 = "Http.exe" fullword ascii
      $s2 = "GOGOGO.bat" fullword ascii
      $s3 = "ip.txt" fullword ascii
   condition:
      all of them
}