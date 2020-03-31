rule CN_Hacktool_ScanPort_Portscanner {
   meta:
      description = "Detects a chinese Portscanner named ScanPort"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      score = 70
      date = "12.10.2014"
   strings:
      $s0 = "LScanPort" fullword wide
      $s1 = "LScanPort Microsoft" fullword wide
      $s2 = "www.yupsoft.com" fullword wide
   condition:
      all of them
}