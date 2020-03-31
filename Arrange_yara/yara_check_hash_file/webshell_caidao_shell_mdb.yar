rule webshell_caidao_shell_mdb {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - file mdb.asp
    family = mdb
    hacker = None
    hash = fbf3847acef4844f3a0d04230f6b9ff9
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[caidao]/shell.mdb
    threattype = caidao
  strings:
    $s1 = "<% execute request(\"ice\")%>a " fullword
  condition:
    all of them
}