rule phvayvv_php_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file phvayvv.php.php.txt"
    family = "None"
    hacker = "None"
    hash = "35fb37f3c806718545d97c6559abd262"
    judge = "unknown"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "{mkdir(\"$dizin/$duzenx2\",777)"
    $s1 = "$baglan=fopen($duzkaydet,'w');"
    $s2 = "PHVayv 1.0"
  condition:
    1 of them
}