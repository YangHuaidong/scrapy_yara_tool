rule backdoor1_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file backdoor1.php.txt"
    family = "None"
    hacker = "None"
    hash = "e1adda1f866367f52de001257b4d6c98"
    judge = "unknown"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "echo \"[DIR] <A HREF=\\\"\".$_SERVER['PHP_SELF'].\"?rep=\".realpath($rep.\".."
    $s2 = "class backdoor {"
    $s4 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?copy=1\\\">Copier un fichier</a> <"
  condition:
    1 of them
}