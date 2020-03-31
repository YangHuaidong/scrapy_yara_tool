rule JS_Suspicious_Obfuscation_Dropbox {
   meta:
      description = "Detects PowerShell AMSI Bypass"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/ItsReallyNick/status/887705105239343104"
      date = "2017-07-19"
      score = 70
   strings:
      $x1 = "j\"+\"a\"+\"v\"+\"a\"+\"s\"+\"c\"+\"r\"+\"i\"+\"p\"+\"t\""
      $x2 = "script:https://www.dropbox.com" ascii
   condition:
      2 of them
}