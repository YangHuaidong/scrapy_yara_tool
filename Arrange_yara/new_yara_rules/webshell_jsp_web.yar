rule webshell_jsp_web {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file web.jsp"
    family = "None"
    hacker = "None"
    hash = "4bc11e28f5dccd0c45a37f2b541b2e98"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<%@page import=\"java.io.*\"%><%@page import=\"java.net.*\"%><%String t=request."
  condition:
    all of them
}