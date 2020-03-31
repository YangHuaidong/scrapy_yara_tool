rule webshell_caidao_shell_hkmjj {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - file hkmjj.asp
    family = hkmjj
    hacker = None
    hash = e7b994fe9f878154ca18b7cde91ad2d0
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[caidao]/shell.hkmjj
    threattype = caidao
  strings:
    $s6 = "codeds=\"Li#uhtxhvw+%{{%,#@%{%#wkhq#hydo#uhtxhvw+%knpmm%,#hqg#li\"  " fullword
  condition:
    all of them
}