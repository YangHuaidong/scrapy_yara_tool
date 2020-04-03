rule webshell_asp_list {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file list.asp"
    family = "None"
    hacker = "None"
    hash = "1cfa493a165eb4b43e6d4cc0f2eab575"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<INPUT TYPE=\"hidden\" NAME=\"type\" value=\"<%=tipo%>\">" fullword
    $s4 = "Response.Write(\"<h3>FILE: \" & file & \"</h3>\")" fullword
  condition:
    all of them
}