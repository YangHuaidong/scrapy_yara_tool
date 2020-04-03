rule webshell_PHP_150 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file 150.php"
    family = "None"
    hacker = "None"
    hash = "400c4b0bed5c90f048398e1d268ce4dc"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "HJ3HjqxclkZfp"
    $s1 = "<? eval(gzinflate(base64_decode('" fullword
  condition:
    all of them
}