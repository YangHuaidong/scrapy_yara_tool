rule FSO_s_phpinj_2 {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file phpinj.php
    family = 2
    hacker = None
    hash = dd39d17e9baca0363cc1c3664e608929
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = FSO[s]/phpinj.2
    threattype = s
  strings:
    $s9 = "<? system(\\$_GET[cpc]);exit; ?>' ,0 ,0 ,0 ,0 INTO"
  condition:
    all of them
}