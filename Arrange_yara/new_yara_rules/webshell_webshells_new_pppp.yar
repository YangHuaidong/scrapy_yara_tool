rule webshell_webshells_new_pppp {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file pppp.php"
    family = "None"
    hacker = "None"
    hash = "cf01cb6e09ee594545693c5d327bdd50"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Mail: chinese@hackermail.com" fullword
    $s3 = "if($_GET[\"hackers\"]==\"2b\"){if ($_SERVER['REQUEST_METHOD'] == 'POST') { echo "
    $s6 = "Site: http://blog.weili.me" fullword
  condition:
    1 of them
}