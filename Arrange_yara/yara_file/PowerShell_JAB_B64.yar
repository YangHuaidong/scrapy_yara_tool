rule PowerShell_JAB_B64 {
   meta:
      description = "Detects base464 encoded $ sign at the beginning of a string"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/ItsReallyNick/status/980915287922040832"
      date = "2018-04-02"
      score = 60
   strings:
      $s1 = "('JAB" ascii wide
      $s2 = "powershell" nocase
   condition:
      filesize < 30KB and all of them
}