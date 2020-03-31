rule FSO_s_remview_2 {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file remview.php
    family = 2
    hacker = None
    hash = b4a09911a5b23e00b55abe546ded691c
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = FSO[s]/remview.2
    threattype = s
  strings:
    $s0 = "<xmp>$out</"
    $s1 = ".mm(\"Eval PHP code\")."
  condition:
    all of them
}