rule APT_MAL_CN_Wocao_keylogger_py {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Strings from Python keylogger"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.fox-it.com/en/news/whitepapers/operation-wocao-shining-a-light-on-one-of-chinas-hidden-hacking-groups/"
    threatname = "None"
    threattype = "None"
  strings:
    $a = "c:\\windows\\temp\\tap.tmp"
    $b = "c:\\windows\\temp\\mrteeh.tmp"
    $c = "GenFileName"
    $d = "outfile"
    $e = "[PASTE:%d]"
  condition:
    3 of them
}