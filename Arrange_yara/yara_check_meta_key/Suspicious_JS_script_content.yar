rule Suspicious_JS_script_content {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-12-02"
    description = "Detects suspicious statements in JavaScript files"
    family = "None"
    hacker = "None"
    hash1 = "fc0fad39b461eb1cfc6be57932993fcea94fca650564271d1b74dd850c81602f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Research on Leviathan https://goo.gl/MZ7dRg"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "new ActiveXObject('WScript.Shell')).Run('cmd /c " ascii
    $x2 = ".Run('regsvr32 /s /u /i:" ascii
    $x3 = "new ActiveXObject('WScript.Shell')).Run('regsvr32 /s" fullword ascii
    $x4 = "args='/s /u /i:" ascii
  condition:
    ( filesize < 10KB and 1 of them )
}