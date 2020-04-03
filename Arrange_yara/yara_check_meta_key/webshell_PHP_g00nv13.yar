rule webshell_PHP_g00nv13 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file g00nv13.php"
    family = "None"
    hacker = "None"
    hash = "35ad2533192fe8a1a76c3276140db820"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "case \"zip\": case \"tar\": case \"rar\": case \"gz\": case \"cab\": cas"
    $s4 = "if(!($sqlcon = @mysql_connect($_SESSION['sql_host'] . ':' . $_SESSION['sql_p"
  condition:
    all of them
}