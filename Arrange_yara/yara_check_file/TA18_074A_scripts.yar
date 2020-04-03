rule TA18_074A_scripts {
   meta:
      description = "Detects malware mentioned in TA18-074A"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://www.us-cert.gov/ncas/alerts/TA18-074A"
      date = "2018-03-16"
      hash1 = "2f159b71183a69928ba8f26b76772ec504aefeac71021b012bd006162e133731"
   strings:
      $s1 = "Running -s cmd /c query user on " ascii
   condition:
      filesize < 600KB and 2 of them
}