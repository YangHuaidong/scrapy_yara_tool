rule PHP_Cloaked_Webshell_SuperFetchExec {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Looks like a webshell cloaked as GIF - http://goo.gl/xFvioC"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/xFvioC"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "else{$d.=@chr(($h[$e[$o]]<<4)+($h[$e[++$o]]));}}eval($d);"
  condition:
    $s0
}