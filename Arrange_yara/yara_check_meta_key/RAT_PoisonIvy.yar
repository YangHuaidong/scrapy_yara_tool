rule RAT_PoisonIvy {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects PoisonIvy RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/PoisonIvy"
    threatname = "None"
    threattype = "None"
  strings:
    $stub = { 04 08 00 53 74 75 62 50 61 74 68 18 04 }
    $string1 = "CONNECT %s:%i HTTP/1.0"
    $string2 = "ws2_32"
    $string3 = "cks=u"
    $string4 = "thj@h"
    $string5 = "advpack"
  condition:
    $stub at 0x1620 and all of ($string*) or (all of them)
}