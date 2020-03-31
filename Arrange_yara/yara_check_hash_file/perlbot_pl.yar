rule perlbot_pl {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - file perlbot.pl.txt
    family = None
    hacker = None
    hash = 7e4deb9884ffffa5d82c22f8dc533a45
    judge = unknown
    reference = None
    threatname = perlbot[pl
    threattype = pl.yar
  strings:
    $s0 = "my @adms=(\"Kelserific\",\"Puna\",\"nod32\")"
    $s1 = "#Acesso a Shel - 1 ON 0 OFF"
  condition:
    1 of them
}