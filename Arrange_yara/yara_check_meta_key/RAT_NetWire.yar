rule RAT_NetWire {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects NetWire RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/NetWire"
    threatname = "None"
    threattype = "None"
  strings:
    $exe1 = "%.2d-%.2d-%.4d"
    $exe2 = "%s%.2d-%.2d-%.4d"
    $exe3 = "[%s] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"
    $exe4 = "wcnwClass"
    $exe5 = "[Ctrl+%c]"
    $exe6 = "SYSTEM\\CurrentControlSet\\Control\\ProductOptions"
    $exe7 = "%s\\.purple\\accounts.xml"
  condition:
    all of them
}