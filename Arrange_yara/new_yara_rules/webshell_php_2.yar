rule webshell_php_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file 2.php"
    family = "None"
    hacker = "None"
    hash = "267c37c3a285a84f541066fc5b3c1747"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<?php assert($_REQUEST[\"c\"]);?> " fullword
  condition:
    all of them
}