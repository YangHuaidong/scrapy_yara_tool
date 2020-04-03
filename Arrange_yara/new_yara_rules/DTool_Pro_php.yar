rule DTool_Pro_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file DTool Pro.php.txt"
    family = "None"
    hacker = "None"
    hash = "366ad973a3f327dfbfb915b0faaea5a6"
    judge = "unknown"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "r3v3ng4ns\\nDigite"
    $s1 = "if(!@opendir($chdir)) $ch_msg=\"dtool: line 1: chdir: It seems that the permissi"
    $s3 = "if (empty($cmd) and $ch_msg==\"\") echo (\"Comandos Exclusivos do DTool Pro\\n"
  condition:
    1 of them
}