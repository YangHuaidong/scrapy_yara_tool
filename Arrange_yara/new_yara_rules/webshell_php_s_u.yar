rule webshell_php_s_u {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file s-u.php"
    family = "None"
    hacker = "None"
    hash = "efc7ba1a4023bcf40f5e912f1dd85b5a"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s6 = "<a href=\"?act=do\"><font color=\"red\">Go Execute</font></a></b><br /><textarea"
  condition:
    all of them
}