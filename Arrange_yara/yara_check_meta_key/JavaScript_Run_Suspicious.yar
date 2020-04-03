rule JavaScript_Run_Suspicious {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-08-23"
    description = "Detects a suspicious Javascript Run command"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://twitter.com/craiu/status/900314063560998912"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "w = new ActiveXObject(" ascii
    $s2 = " w.Run(r);" fullword ascii
  condition:
    all of them
}