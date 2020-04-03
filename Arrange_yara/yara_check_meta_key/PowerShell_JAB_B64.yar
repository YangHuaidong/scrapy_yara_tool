rule PowerShell_JAB_B64 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-04-02"
    description = "Detects base464 encoded $ sign at the beginning of a string"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://twitter.com/ItsReallyNick/status/980915287922040832"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "('JAB" ascii wide
    $s2 = "powershell" nocase
  condition:
    filesize < 30KB and all of them
}