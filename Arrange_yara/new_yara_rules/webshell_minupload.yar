rule webshell_minupload {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file minupload.jsp"
    family = "None"
    hacker = "None"
    hash = "ec905a1395d176c27f388d202375bdf9"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">   " fullword
    $s9 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859"
  condition:
    all of them
}