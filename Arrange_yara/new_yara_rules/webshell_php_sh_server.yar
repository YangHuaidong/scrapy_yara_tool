rule webshell_php_sh_server {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file server.php"
    family = "None"
    hacker = "None"
    hash = "d87b019e74064aa90e2bb143e5e16cfa"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "eval(getenv('HTTP_CODE'));" fullword
  condition:
    all of them
}