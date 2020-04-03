rule RAT_DarkRAT {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects DarkRAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/DarkRAT"
    threatname = "None"
    threattype = "None"
  strings:
    $a = "@1906dark1996coder@"
    $b = "SHEmptyRecycleBinA"
    $c = "mciSendStringA"
    $d = "add_Shutdown"
    $e = "get_SaveMySettingsOnExit"
    $f = "get_SpecialDirectories"
    $g = "Client.My"
  condition:
    all of them
}