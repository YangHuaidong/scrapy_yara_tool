rule FSO_s_phvayv_2 {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file phvayv.php
    family = 2
    hacker = None
    hash = 205ecda66c443083403efb1e5c7f7878
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = FSO[s]/phvayv.2
    threattype = s
  strings:
    $s2 = "rows=\"24\" cols=\"122\" wrap=\"OFF\">XXXX</textarea></font><font"
  condition:
    all of them
}