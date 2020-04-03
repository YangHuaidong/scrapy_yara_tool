rule RAT_AAR {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects AAR RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/AAR"
    threatname = "None"
    threattype = "None"
  strings:
    $a = "Hashtable"
    $b = "get_IsDisposed"
    $c = "TripleDES"
    $d = "testmemory.FRMMain.resources"
    $e = "$this.Icon" wide
    $f = "{11111-22222-20001-00001}" wide
  condition:
    all of them
}