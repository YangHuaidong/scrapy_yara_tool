rule RAT_xRAT {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects xRAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/xRat"
    threatname = "None"
    threattype = "None"
  strings:
    $v1a = "DecodeProductKey"
    $v1b = "StartHTTPFlood"
    $v1c = "CodeKey"
    $v1d = "MESSAGEBOX"
    $v1e = "GetFilezillaPasswords"
    $v1f = "DataIn"
    $v1g = "UDPzSockets"
    $v1h = { 52 00 54 00 5f 00 52 00 43 00 44 00 41 00 54 00 41 }
    $v2a = "<URL>k__BackingField"
    $v2b = "<RunHidden>k__BackingField"
    $v2c = "DownloadAndExecute"
    $v2d = "-CHECK & PING -n 2 127.0.0.1 & EXIT" wide
    $v2e = "england.png" wide
    $v2f = "Showed Messagebox" wide
  condition:
    all of ($v1*) or all of ($v2*)
}