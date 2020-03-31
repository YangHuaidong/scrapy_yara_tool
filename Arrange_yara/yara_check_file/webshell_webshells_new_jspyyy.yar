rule webshell_webshells_new_jspyyy {
  meta:
    author = Spider
    comment = None
    date = 2014/03/28
    description = Web shells - generated from file jspyyy.jsp
    family = jspyyy
    hacker = None
    hash = b291bf3ccc9dac8b5c7e1739b8fa742e
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[webshells]/new.jspyyy
    threattype = webshells
  strings:
    $s0 = "<%@page import=\"java.io.*\"%><%if(request.getParameter(\"f\")"
  condition:
    all of them
}