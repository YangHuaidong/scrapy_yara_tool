rule WCE_in_memory {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-08-28"
    description = "Detects Windows Credential Editor (WCE) in memory (and also on disk)"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    score = 80
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "wkKUSvflehHr::o:t:s:c:i:d:a:g:" fullword ascii
    $s2 = "wceaux.dll" fullword ascii
  condition:
    all of them
}