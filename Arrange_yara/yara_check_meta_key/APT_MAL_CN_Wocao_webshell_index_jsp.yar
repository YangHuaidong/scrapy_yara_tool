rule APT_MAL_CN_Wocao_webshell_index_jsp {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Strings from the index.jsp socket tunnel"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "X-CMD"
    $x2 = "X-STATUS"
    $x3 = "X-TARGET"
    $x4 = "X-ERROR"
    $a = "out.print(\"All seems fine.\");"
  condition:
    all of ($x*) and $a
}