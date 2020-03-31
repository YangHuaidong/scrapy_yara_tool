rule CN_Hacktool_SSPort_Portscanner {
   meta:
      description = "Detects a chinese Portscanner named SSPort"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      score = 70
      date = "12.10.2014"
   strings:
      $s0 = "Golden Fox" fullword wide
      $s1 = "Syn Scan Port" fullword wide
      $s2 = "CZ88.NET" fullword wide
   condition:
      all of them
}