rule webshell_jsp_asd {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file asd.jsp"
    family = "None"
    hacker = "None"
    hash = "a042c2ca64176410236fcc97484ec599"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s3 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%>" fullword
    $s6 = "<input size=\"100\" value=\"<%=application.getRealPath(\"/\") %>\" name=\"url"
  condition:
    all of them
}