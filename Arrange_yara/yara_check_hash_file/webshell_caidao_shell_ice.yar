rule webshell_caidao_shell_ice {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - file ice.asp
    family = ice
    hacker = None
    hash = 6560b436d3d3bb75e2ef3f032151d139
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[caidao]/shell.ice
    threattype = caidao
  strings:
    $s0 = "<%eval request(\"ice\")%>" fullword
  condition:
    all of them
}