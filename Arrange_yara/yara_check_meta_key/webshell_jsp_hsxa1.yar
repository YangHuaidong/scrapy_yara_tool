rule webshell_jsp_hsxa1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file hsxa1.jsp"
    family = "None"
    hacker = "None"
    hash = "5686d5a38c6f5b8c55095af95c2b0244"
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