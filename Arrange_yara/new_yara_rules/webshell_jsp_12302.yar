rule webshell_jsp_12302 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file 12302.jsp"
    family = "None"
    hacker = "None"
    hash = "a3930518ea57d899457a62f372205f7f"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "</font><%out.print(request.getRealPath(request.getServletPath())); %>" fullword
    $s1 = "<%@page import=\"java.io.*,java.util.*,java.net.*\"%>" fullword
    $s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
  condition:
    all of them
}