rule WCE_in_memory {
   meta:
      description = "Detects Windows Credential Editor (WCE) in memory (and also on disk)"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      score = 80
      date = "2016-08-28"
   strings:
      $s1 = "wkKUSvflehHr::o:t:s:c:i:d:a:g:" fullword ascii
      $s2 = "wceaux.dll" fullword ascii
   condition:
      all of them
}