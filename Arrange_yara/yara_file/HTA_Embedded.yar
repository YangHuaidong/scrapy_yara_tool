rule HTA_Embedded {
   meta:
      description = "Detects an embedded HTA file"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/msftmmpc/status/877396932758560768"
      date = "2017-06-21"
      score = 50
      hash1 = "ca7b653cf41e980c44311b2cd701ed666f8c1dbc"
   strings:
      $s1 = "<hta:application windowstate=\"minimize\"/>"
   condition:
      $s1 and not $s1 in (0..50000)
}