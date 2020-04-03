rule RAT_njRat {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects njRAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/njRat"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = { 7c 00 27 00 7c 00 27 00 7c } // |'|'|
    $s2 = "netsh firewall add allowedprogram" wide
    $s3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
    $s4 = "yyyy-MM-dd" wide
    $v1 = "cmd.exe /k ping 0 & del" wide
    $v2 = "cmd.exe /c ping 127.0.0.1 & del" wide
    $v3 = "cmd.exe /c ping 0 -n 2 & del" wide
  condition:
    all of ($s*) and any of ($v*)
}