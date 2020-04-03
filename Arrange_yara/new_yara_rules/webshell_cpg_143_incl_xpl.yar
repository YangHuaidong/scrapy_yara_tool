rule webshell_cpg_143_incl_xpl {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file cpg_143_incl_xpl.php"
    family = "None"
    hacker = "None"
    hash = "5937b131b67d8e0afdbd589251a5e176"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "$data=\"username=\".urlencode($USER).\"&password=\".urlencode($PA"
    $s5 = "fputs($sun_tzu,\"<?php echo \\\"Hi Master!\\\";ini_set(\\\"max_execution_time"
  condition:
    1 of them
}