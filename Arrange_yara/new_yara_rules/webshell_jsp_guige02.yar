rule webshell_jsp_guige02 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file guige02.jsp"
    family = "None"
    hacker = "None"
    hash = "a3b8b2280c56eaab777d633535baf21d"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "????????????????%><html><head><title>hahahaha</title></head><body bgcolor=\"#fff"
    $s1 = "<%@page contentType=\"text/html; charset=GBK\" import=\"java.io.*;\"%><%!private"
  condition:
    all of them
}