rule WCE_Modified_1_1014 {
   meta:
      description = "Modified (packed) version of Windows Credential Editor"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      hash = "09a412ac3c85cedce2642a19e99d8f903a2e0354"
      score = 70
   strings:
      $s0 = "LSASS.EXE" fullword ascii
      $s1 = "_CREDS" ascii
      $s9 = "Using WCE " ascii
   condition:
      all of them
}