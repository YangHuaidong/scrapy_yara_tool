rule shellbot_pl {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file shellbot.pl.txt"
    family = "None"
    hacker = "None"
    hash = "b2a883bc3c03a35cfd020dd2ace4bab8"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "ShellBOT"
    $s1 = "PacktsGr0up"
    $s2 = "CoRpOrAtIoN"
    $s3 = "# Servidor de irc que vai ser usado "
    $s4 = "/^ctcpflood\\s+(\\d+)\\s+(\\S+)"
  condition:
    2 of them
}