rule APT_FIN7_EXE_Sample_Aug18_3 {
   meta:
      description = "Detects sample from FIN7 report in August 2018"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2018/08/fin7-pursuing-an-enigmatic-and-evasive-global-criminal-operation.html"
      date = "2018-08-01"
      hash1 = "995b90281774798a376db67f906a126257d314efc21b03768941f2f819cf61a6"
   strings:
      $s1 = "cvzdfhtjkdhbfszngjdng" fullword ascii
      $s2 = "sdfkjdfjfhgurgvncmnvmfdjdkfjdkfjdf" fullword wide
   condition:
      uint16(0) == 0x5a4d and filesize < 50KB and 1 of them
}