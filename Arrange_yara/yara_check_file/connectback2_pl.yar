rule connectback2_pl {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - file connectback2.pl.txt
    family = None
    hacker = None
    hash = 473b7d226ea6ebaacc24504bd740822e
    judge = unknown
    reference = None
    threatname = connectback2[pl
    threattype = pl.yar
  strings:
    $s0 = "#We Are: MasterKid, AleXutz, FatMan & MiKuTuL                                   "
    $s1 = "echo --==Userinfo==-- ; id;echo;echo --==Directory==-- ; pwd;echo; echo --==Shel"
    $s2 = "ConnectBack Backdoor"
  condition:
    1 of them
}