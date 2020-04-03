rule webshell_php_list {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file list.php"
    family = "None"
    hacker = "None"
    hash = "922b128ddd90e1dc2f73088956c548ed"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "// list.php = Directory & File Listing" fullword
    $s2 = "    echo \"( ) <a href=?file=\" . $fichero . \"/\" . $filename . \">\" . $filena"
    $s9 = "// by: The Dark Raver" fullword
  condition:
    1 of them
}