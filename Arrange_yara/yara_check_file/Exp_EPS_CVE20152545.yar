rule Exp_EPS_CVE20152545 {
   meta:
      description = "Detects EPS Word Exploit CVE-2015-2545"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research - ME"
      date = "2017-07-19"
      score = 70
   strings:
      $s1 = "word/media/image1.eps" ascii
      $s2 = "-la;7(la+" ascii
   condition:
      uint16(0) == 0x4b50 and ( $s1 and #s2 > 20 )
}