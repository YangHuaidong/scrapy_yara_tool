rule iMHaPFtp {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file iMHaPFtp.php"
    family = "None"
    hacker = "None"
    hash = "12911b73bc6a5d313b494102abcf5c57"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "echo \"\\t<th class=\\\"permission_header\\\"><a href=\\\"$self?{$d}sort=permission$r\\\">"
  condition:
    all of them
}