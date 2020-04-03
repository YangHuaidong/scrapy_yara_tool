rule Test_php_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Test.php.php.txt"
    family = "None"
    hacker = "None"
    hash = "77e331abd03b6915c6c6c7fe999fcb50"
    judge = "unknown"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "$yazi = \"test\" . \"\\r\\n\";" fullword
    $s2 = "fwrite ($fp, \"$yazi\");" fullword
    $s3 = "$entry_line=\"HACKed by EntriKa\";" fullword
  condition:
    1 of them
}