rule webshell_jsp_tree {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file tree.jsp"
    family = "None"
    hacker = "None"
    hash = "bcdf7bbf7bbfa1ffa4f9a21957dbcdfa"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s5 = "$('#tt2').tree('options').url = \"selectChild.action?checki"
    $s6 = "String basePath = request.getScheme()+\"://\"+request.getServerName()+\":\"+requ"
  condition:
    all of them
}