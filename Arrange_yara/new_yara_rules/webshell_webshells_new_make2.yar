rule webshell_webshells_new_make2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file make2.php"
    family = "None"
    hacker = "None"
    hash = "9af195491101e0816a263c106e4c145e"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "error_reporting(0);session_start();header(\"Content-type:text/html;charset=utf-8"
  condition:
    all of them
}