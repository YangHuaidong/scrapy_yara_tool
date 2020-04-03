rule webshell_jsp_jshell {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file jshell.jsp"
    family = "None"
    hacker = "None"
    hash = "124b22f38aaaf064cef14711b2602c06"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "kXpeW[\"" fullword
    $s4 = "[7b:g0W@W<" fullword
    $s5 = "b:gHr,g<" fullword
    $s8 = "RhV0W@W<" fullword
    $s9 = "S_MR(u7b" fullword
  condition:
    all of them
}