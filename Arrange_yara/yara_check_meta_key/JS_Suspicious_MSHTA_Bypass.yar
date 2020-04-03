rule JS_Suspicious_MSHTA_Bypass {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-07-19"
    description = "Detects MSHTA Bypass"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://twitter.com/ItsReallyNick/status/887705105239343104"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "mshtml,RunHTMLApplication" ascii
    $s2 = "new ActiveXObject(\"WScript.Shell\").Run(" ascii
    $s3 = "/c start mshta j" ascii nocase
  condition:
    2 of them
}