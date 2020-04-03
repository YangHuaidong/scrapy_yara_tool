rule shell_php_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file shell.php.php.txt"
    family = "None"
    hacker = "None"
    hash = "1a95f0163b6dea771da1694de13a3d8d"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "/* We have found the parent dir. We must be carefull if the parent " fullword
    $s2 = "$tmpfile = tempnam('/tmp', 'phpshell');"
    $s3 = "if (ereg('^[[:blank:]]*cd[[:blank:]]+([^;]+)$', $command, $regs)) {" fullword
  condition:
    1 of them
}