rule sql_php_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file sql.php.php.txt"
    family = "None"
    hacker = "None"
    hash = "8334249cbb969f2d33d678fec2b680c5"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "fputs ($fp, \"# RST MySQL tools\\r\\n# Home page: http://rst.void.ru\\r\\n#"
    $s2 = "http://rst.void.ru"
    $s3 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&"
  condition:
    1 of them
}