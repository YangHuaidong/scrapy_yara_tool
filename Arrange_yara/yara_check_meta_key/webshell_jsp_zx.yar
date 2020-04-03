rule webshell_jsp_zx {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file zx.jsp"
    family = "None"
    hacker = "None"
    hash = "67627c264db1e54a4720bd6a64721674"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application.g"
  condition:
    all of them
}