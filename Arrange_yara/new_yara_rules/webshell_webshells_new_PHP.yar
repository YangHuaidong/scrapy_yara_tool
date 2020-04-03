rule webshell_webshells_new_PHP {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file PHP.php"
    family = "None"
    hacker = "None"
    hash = "a524e7ae8d71e37d2fd3e5fbdab405ea"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "echo \"<font color=blue>Error!</font>\";" fullword
    $s2 = "<input type=\"text\" size=61 name=\"f\" value='<?php echo $_SERVER[\"SCRIPT_FILE"
    $s5 = " - ExpDoor.com</title>" fullword
    $s10 = "$f=fopen($_POST[\"f\"],\"w\");" fullword
    $s12 = "<textarea name=\"c\" cols=60 rows=15></textarea><br>" fullword
  condition:
    1 of them
}