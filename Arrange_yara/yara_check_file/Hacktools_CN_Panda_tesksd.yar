rule Hacktools_CN_Panda_tesksd {
   meta:
      description = "Disclosed hacktool set - file tesksd.jpg"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      date = "17.11.14"
      score = 60
      hash = "922147b3e1e6cf1f5dd5f64a4e34d28bdc9128cb"
   strings:
      $s0 = "name=\"Microsoft.Windows.Common-Controls\" " fullword ascii
      $s1 = "ExeMiniDownload.exe" fullword wide
      $s16 = "POST %Hs" fullword ascii
   condition:
      all of them
}