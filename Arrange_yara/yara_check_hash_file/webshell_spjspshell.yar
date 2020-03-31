rule webshell_spjspshell {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - file spjspshell.jsp
    family = None
    hacker = None
    hash = d39d51154aaad4ba89947c459a729971
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[spjspshell
    threattype = spjspshell.yar
  strings:
    $s7 = "Unix:/bin/sh -c tar vxf xxx.tar Windows:c:\\winnt\\system32\\cmd.exe /c type c:"
  condition:
    all of them
}