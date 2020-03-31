rule ironshell_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - file ironshell.php.txt
    family = None
    hacker = None
    hash = 8bfa2eeb8a3ff6afc619258e39fded56
    judge = unknown
    reference = None
    threatname = ironshell[php
    threattype = php.yar
  strings:
    $s0 = "www.ironwarez.info"
    $s1 = "$cookiename = \"wieeeee\";"
    $s2 = "~ Shell I"
    $s3 = "www.rootshell-team.info"
    $s4 = "setcookie($cookiename, $_POST['pass'], time()+3600);"
  condition:
    1 of them
}