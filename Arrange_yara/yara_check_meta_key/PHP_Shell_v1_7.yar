rule PHP_Shell_v1_7 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file PHP_Shell_v1.7.php"
    family = "None"
    hacker = "None"
    hash = "b5978501c7112584532b4ca6fb77cba5"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s8 = "<title>[ADDITINAL TITTLE]-phpShell by:[YOURNAME]"
  condition:
    all of them
}