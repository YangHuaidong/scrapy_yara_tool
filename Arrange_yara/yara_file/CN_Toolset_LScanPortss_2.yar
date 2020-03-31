rule CN_Toolset_LScanPortss_2 {
   meta:
      description = "Detects a Chinese hacktool from a disclosed toolset - file LScanPortss.exe"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "http://qiannao.com/ls/905300366/33834c0c/"
      date = "2015/03/30"
      score = 70
      hash = "4631ec57756466072d83d49fbc14105e230631a0"
   strings:
      $s1 = "LScanPort.EXE" fullword wide
      $s3 = "www.honker8.com" fullword wide
      $s4 = "DefaultPort.lst" fullword ascii
      $s5 = "Scan over.Used %dms!" fullword ascii
      $s6 = "www.hf110.com" fullword wide
      $s15 = "LScanPort Microsoft " fullword wide
      $s18 = "L-ScanPort2.0 CooFly" fullword wide
   condition:
      4 of them
}