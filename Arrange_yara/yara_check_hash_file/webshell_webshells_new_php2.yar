rule webshell_webshells_new_php2 {
  meta:
    author = Spider
    comment = None
    date = 2014/03/28
    description = Web shells - generated from file php2.php
    family = php2
    hacker = None
    hash = fbf2e76e6f897f6f42b896c855069276
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[webshells]/new.php2
    threattype = webshells
  strings:
    $s0 = "<?php $s=@$_GET[2];if(md5($s.$s)=="
  condition:
    all of them
}