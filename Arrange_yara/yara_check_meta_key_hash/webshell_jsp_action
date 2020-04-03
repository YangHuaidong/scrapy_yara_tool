rule webshell_jsp_action {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file action.jsp"
    family = "None"
    hacker = "None"
    hash = "5a7d931094f5570aaf5b7b3b06c3d8c0"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";" fullword
    $s6 = "<%@ page contentType=\"text/html;charset=gb2312\"%>" fullword
  condition:
    all of them
}