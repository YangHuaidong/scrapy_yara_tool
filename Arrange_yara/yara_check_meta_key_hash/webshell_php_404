rule webshell_php_404 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file 404.php"
    family = "None"
    hacker = "None"
    hash = "ced050df5ca42064056a7ad610a191b3"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "$pass = md5(md5(md5($pass)));" fullword
  condition:
    all of them
}