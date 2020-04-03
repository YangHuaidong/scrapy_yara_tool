rule webshell_php_cmd {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file cmd.php"
    family = "None"
    hacker = "None"
    hash = "c38ae5ba61fd84f6bbbab98d89d8a346"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "if($_GET['cmd']) {" fullword
    $s1 = "// cmd.php = Command Execution" fullword
    $s7 = "  system($_GET['cmd']);" fullword
  condition:
    all of them
}