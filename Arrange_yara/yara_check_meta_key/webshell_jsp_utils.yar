rule webshell_jsp_utils {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file utils.jsp"
    family = "None"
    hacker = "None"
    hash = "9827ba2e8329075358b8e8a53e20d545"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "ResultSet r = c.getMetaData().getTables(null, null, \"%\", t);" fullword
    $s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"
  condition:
    all of them
}