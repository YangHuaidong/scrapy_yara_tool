rule RAT_BlueBanana {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects BlueBanana RAT"
    family = "None"
    filetype = "Java"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/BlueBanana"
    threatname = "None"
    threattype = "None"
  strings:
    $meta = "META-INF"
    $conf = "config.txt"
    $a = "a/a/a/a/f.class"
    $b = "a/a/a/a/l.class"
    $c = "a/a/a/b/q.class"
    $d = "a/a/a/b/v.class"
  condition:
    all of them
}