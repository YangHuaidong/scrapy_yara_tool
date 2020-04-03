rule webshell_jsp_sys3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file sys3.jsp"
    family = "None"
    hacker = "None"
    hash = "b3028a854d07674f4d8a9cf2fb6137ec"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">" fullword
    $s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
    $s9 = "<%@page contentType=\"text/html;charset=gb2312\"%>" fullword
  condition:
    all of them
}