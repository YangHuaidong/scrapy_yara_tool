rule webshell_jsp_123 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file 123.jsp"
    family = "None"
    hacker = "None"
    hash = "c691f53e849676cac68a38d692467641"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<font color=\"blue\">??????????????????:</font><input type=\"text\" size=\"7"
    $s3 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
    $s9 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">    " fullword
  condition:
    all of them
}