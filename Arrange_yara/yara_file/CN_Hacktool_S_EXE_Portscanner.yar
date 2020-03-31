rule CN_Hacktool_S_EXE_Portscanner {
   meta:
      description = "Detects a chinese Portscanner named s.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      score = 70
      date = "12.10.2014"
   strings:
      $s0 = "\\Result.txt" fullword ascii
      $s1 = "By:ZT QQ:376789051" fullword ascii
      $s2 = "(http://www.eyuyan.com)" fullword wide
   condition:
      all of them
}