rule RAT_Bandook {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects Bandook RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/bandook"
    threatname = "None"
    threattype = "None"
  strings:
    $a = "aaaaaa1|"
    $b = "aaaaaa2|"
    $c = "aaaaaa3|"
    $d = "aaaaaa4|"
    $e = "aaaaaa5|"
    $f = "%s%d.exe"
    $g = "astalavista"
    $h = "givemecache"
    $i = "%s\\system32\\drivers\\blogs\\*"
    $j = "bndk13me"
  condition:
    all of them
}