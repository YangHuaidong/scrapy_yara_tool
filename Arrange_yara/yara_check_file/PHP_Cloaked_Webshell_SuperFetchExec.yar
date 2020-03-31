rule PHP_Cloaked_Webshell_SuperFetchExec {
  meta:
    author = Spider
    comment = None
    date = None
    description = Looks like a webshell cloaked as GIF - http://goo.gl/xFvioC
    family = SuperFetchExec
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://goo.gl/xFvioC
    score = 50
    threatname = PHP[Cloaked]/Webshell.SuperFetchExec
    threattype = Cloaked
  strings:
    $s0 = "else{$d.=@chr(($h[$e[$o]]<<4)+($h[$e[++$o]]));}}eval($d);"
  condition:
    $s0
}