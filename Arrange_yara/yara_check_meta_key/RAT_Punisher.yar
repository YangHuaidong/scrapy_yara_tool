rule RAT_Punisher {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects Punisher RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/Punisher"
    threatname = "None"
    threattype = "None"
  strings:
    $a = "abccba"
    $b = { 5c 00 68 00 66 00 68 00 2e 00 76 00 62 00 73 }
    $c = { 5c 00 73 00 63 00 2e 00 76 00 62 00 73 }
    $d = "SpyTheSpy" wide ascii
    $e = "wireshark" wide
    $f = "apateDNS" wide
    $g = "abccbaDanabccb"
  condition:
    all of them
}