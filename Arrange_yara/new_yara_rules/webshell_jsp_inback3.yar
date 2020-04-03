rule webshell_jsp_inback3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file inback3.jsp"
    family = "None"
    hacker = "None"
    hash = "ea5612492780a26b8aa7e5cedd9b8f4e"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<%if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application"
  condition:
    all of them
}