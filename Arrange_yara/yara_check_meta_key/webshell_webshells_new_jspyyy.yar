rule webshell_webshells_new_jspyyy {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file jspyyy.jsp"
    family = "None"
    hacker = "None"
    hash = "b291bf3ccc9dac8b5c7e1739b8fa742e"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<%@page import=\"java.io.*\"%><%if(request.getParameter(\"f\")"
  condition:
    all of them
}