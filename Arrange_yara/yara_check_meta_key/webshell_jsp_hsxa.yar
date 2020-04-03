rule webshell_jsp_hsxa {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file hsxa.jsp"
    family = "None"
    hacker = "None"
    hash = "d0e05f9c9b8e0b3fa11f57d9ab800380"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%><jsp:directive.page import=\"ja"
  condition:
    all of them
}