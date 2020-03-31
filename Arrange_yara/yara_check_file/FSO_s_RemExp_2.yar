rule FSO_s_RemExp_2 {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file RemExp.asp
    family = 2
    hacker = None
    hash = b69670ecdbb40012c73686cd22696eeb
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = FSO[s]/RemExp.2
    threattype = s
  strings:
    $s2 = " Then Response.Write \""
    $s3 = "<a href= \"<%=Request.ServerVariables(\"script_name\")%>"
  condition:
    all of them
}