rule FSO_s_phvayv {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file phvayv.php"
    family = "None"
    hacker = "None"
    hash = "205ecda66c443083403efb1e5c7f7878"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "wrap=\"OFF\">XXXX</textarea></font><font face"
  condition:
    all of them
}