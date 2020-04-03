rule JS_Suspicious_Obfuscation_Dropbox {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-07-19"
    description = "Detects PowerShell AMSI Bypass"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://twitter.com/ItsReallyNick/status/887705105239343104"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "j\"+\"a\"+\"v\"+\"a\"+\"s\"+\"c\"+\"r\"+\"i\"+\"p\"+\"t\""
    $x2 = "script:https://www.dropbox.com" ascii
  condition:
    2 of them
}