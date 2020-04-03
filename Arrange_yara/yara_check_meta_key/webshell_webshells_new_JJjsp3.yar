rule webshell_webshells_new_JJjsp3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/03/28"
    description = "Web shells - generated from file JJjsp3.jsp"
    family = "None"
    hacker = "None"
    hash = "949ffee1e07a1269df7c69b9722d293e"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%!S"
  condition:
    all of them
}