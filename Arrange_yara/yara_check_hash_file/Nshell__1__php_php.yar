rule Nshell__1__php_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - file Nshell (1).php.php.txt
    family = 
    hacker = None
    hash = 973fc89694097a41e684b43a21b1b099
    judge = unknown
    reference = None
    threatname = Nshell[]/1..php.php
    threattype = 
  strings:
    $s0 = "echo \"Command : <INPUT TYPE=text NAME=cmd value=\".@stripslashes(htmlentities($"
    $s1 = "if(!$whoami)$whoami=exec(\"whoami\"); echo \"whoami :\".$whoami.\"<br>\";" fullword
  condition:
    1 of them
}