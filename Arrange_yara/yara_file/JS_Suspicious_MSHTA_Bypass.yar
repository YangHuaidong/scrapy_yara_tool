rule JS_Suspicious_MSHTA_Bypass {
   meta:
      description = "Detects MSHTA Bypass"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://twitter.com/ItsReallyNick/status/887705105239343104"
      date = "2017-07-19"
      score = 70
   strings:
      $s1 = "mshtml,RunHTMLApplication" ascii
      $s2 = "new ActiveXObject(\"WScript.Shell\").Run(" ascii
      $s3 = "/c start mshta j" ascii nocase
   condition:
      2 of them
}