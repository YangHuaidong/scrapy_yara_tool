rule webshell_phpshell3 {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - file phpshell3.php
    family = None
    hacker = None
    hash = 76117b2ee4a7ac06832d50b2d04070b8
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[phpshell3
    threattype = phpshell3.yar
  strings:
    $s2 = "<input name=\"nounce\" type=\"hidden\" value=\"<?php echo $_SESSION['nounce'];"
    $s5 = "<p>Username: <input name=\"username\" type=\"text\" value=\"<?php echo $userna"
    $s7 = "$_SESSION['output'] .= \"cd: could not change to: $new_dir\\n\";" fullword
  condition:
    2 of them
}