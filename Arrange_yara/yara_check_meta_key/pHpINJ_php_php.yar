rule pHpINJ_php_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file pHpINJ.php.php.txt"
    family = "None"
    hacker = "None"
    hash = "d7a4b0df45d34888d5a09f745e85733f"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "News Remote PHP Shell Injection"
    $s3 = "Php Shell <br />" fullword
    $s4 = "<input type = \"text\" name = \"url\" value = \""
  condition:
    2 of them
}