rule webshell_php {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file webshell.php.txt"
    family = "None"
    hacker = "None"
    hash = "e425241b928e992bde43dd65180a4894"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "<die(\"Couldn't Read directory, Blocked!!!\");"
    $s3 = "PHP Web Shell"
  condition:
    all of them
}