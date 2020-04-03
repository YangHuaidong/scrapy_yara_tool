rule webshell_PH_Vayv_PH_Vayv {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file PH Vayv.php"
    family = "None"
    hacker = "None"
    hash = "35fb37f3c806718545d97c6559abd262"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px in"
    $s4 = "<font color=\"#858585\">SHOPEN</font></a></font><font face=\"Verdana\" style"
  condition:
    1 of them
}