rule APT_FIN7_EXE_Sample_Aug18_2 {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "60cd98fc4cb2ae474e9eab81cd34fd3c3f638ad77e4f5d5c82ca46f3471c3020"
   strings:
      $s1 = "constructor or from DllMain." fullword ascii
      $s2 = "Network Software Ltd0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 400KB and all of them
}