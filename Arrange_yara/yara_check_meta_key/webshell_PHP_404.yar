rule webshell_PHP_404 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file 404.php"
    family = "None"
    hacker = "None"
    hash = "078c55ac475ab9e028f94f879f548bca"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s4 = "<span>Posix_getpwuid (\"Read\" /etc/passwd)"
  condition:
    all of them
}