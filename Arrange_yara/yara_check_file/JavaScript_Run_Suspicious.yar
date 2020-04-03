rule JavaScript_Run_Suspicious {
   meta:
      description = "Detects a suspicious Javascript Run command"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/craiu/status/900314063560998912"
      score = 60
      date = "2017-08-23"
   strings:
      $s1 = "w = new ActiveXObject(" ascii
      $s2 = " w.Run(r);" fullword ascii
   condition:
      all of them
}