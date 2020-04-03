rule jsp_reverse_jsp {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file jsp-reverse.jsp.txt"
    family = "None"
    hacker = "None"
    hash = "8b0e6779f25a17f0ffb3df14122ba594"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "// backdoor.jsp"
    $s1 = "JSP Backdoor Reverse Shell"
    $s2 = "http://michaeldaw.org"
  condition:
    2 of them
}