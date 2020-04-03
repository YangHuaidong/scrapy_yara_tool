rule lamashell_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file lamashell.php.txt"
    family = "None"
    hacker = "None"
    hash = "de9abc2e38420cad729648e93dfc6687"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "lama's'hell" fullword
    $s1 = "if($_POST['king'] == \"\") {"
    $s2 = "if (move_uploaded_file($_FILES['fila']['tmp_name'], $curdir.\"/\".$_FILES['f"
  condition:
    1 of them
}