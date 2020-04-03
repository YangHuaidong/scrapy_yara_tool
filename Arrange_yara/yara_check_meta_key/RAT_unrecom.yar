rule RAT_unrecom {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects unrecom RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/unrecom"
    threatname = "None"
    threattype = "None"
  strings:
    $meta = "META-INF"
    $conf = "load/ID"
    $a = "load/JarMain.class"
    $b = "load/MANIFEST.MF"
    $c = "plugins/UnrecomServer.class"
  condition:
    all of them
}