rule webshell_jsp_list1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file list1.jsp"
    family = "None"
    hacker = "None"
    hash = "8d9e5afa77303c9c01ff34ea4e7f6ca6"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "case 's':ConnectionDBM(out,encodeChange(request.getParameter(\"drive"
    $s9 = "return \"<a href=\\\"javascript:delFile('\"+folderReplace(file)+\"')\\\""
  condition:
    all of them
}