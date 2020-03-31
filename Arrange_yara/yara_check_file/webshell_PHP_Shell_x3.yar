rule webshell_PHP_Shell_x3 {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - file PHP Shell.php
    family = x3
    hacker = None
    hash = a2f8fa4cce578fc9c06f8e674b9e63fd
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[PHP]/Shell.x3
    threattype = PHP
  strings:
    $s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">["
    $s6 = "echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input"
    $s9 = "if  ( ( (isset($http_auth_user) ) && (isset($http_auth_pass)) ) && ( !isset("
  condition:
    2 of them
}