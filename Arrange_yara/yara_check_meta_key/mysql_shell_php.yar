rule mysql_shell_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file mysql_shell.php.txt"
    family = "None"
    hacker = "None"
    hash = "d42aec2891214cace99b3eb9f3e21a63"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "SooMin Kim"
    $s1 = "smkim@popeye.snu.ac.kr"
    $s2 = "echo \"<td><a href='$PHP_SELF?action=deleteData&dbname=$dbname&tablename=$tablen"
  condition:
    1 of them
}