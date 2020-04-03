rule webshell_webshell_cnseay02_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file webshell-cnseay02-1.php"
    family = "None"
    hacker = "None"
    hash = "95fc76081a42c4f26912826cb1bd24b1"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "(93).$_uU(41).$_uU(59);$_fF=$_uU(99).$_uU(114).$_uU(101).$_uU(97).$_uU(116).$_uU"
  condition:
    all of them
}