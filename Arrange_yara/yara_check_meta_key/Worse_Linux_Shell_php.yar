rule Worse_Linux_Shell_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Worse Linux Shell.php.txt"
    family = "None"
    hacker = "None"
    hash = "8338c8d9eab10bd38a7116eb534b5fa2"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "print \"<tr><td><b>Server is:</b></td><td>\".$_SERVER['SERVER_SIGNATURE'].\"</td"
    $s2 = "print \"<tr><td><b>Execute command:</b></td><td><input size=100 name=\\\"_cmd"
  condition:
    1 of them
}