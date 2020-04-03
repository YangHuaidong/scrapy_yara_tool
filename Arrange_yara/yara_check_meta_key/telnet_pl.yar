rule telnet_pl {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file telnet.pl.txt"
    family = "None"
    hacker = "None"
    hash = "dd9dba14383064e219e29396e242c1ec"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "W A R N I N G: Private Server"
    $s2 = "$Message = q$<pre><font color=\"#669999\"> _____  _____  _____          _____   "
  condition:
    all of them
}