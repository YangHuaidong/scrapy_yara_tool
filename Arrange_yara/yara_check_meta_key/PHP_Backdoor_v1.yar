rule PHP_Backdoor_v1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file PHP Backdoor v1.php"
    family = "None"
    hacker = "None"
    hash = "0506ba90759d11d78befd21cabf41f3d"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s5 = "echo\"<form method=\\\"POST\\\" action=\\\"\".$_SERVER['PHP_SELF'].\"?edit=\".$th"
    $s8 = "echo \"<a href=\\\"\".$_SERVER['PHP_SELF'].\"?proxy"
  condition:
    all of them
}