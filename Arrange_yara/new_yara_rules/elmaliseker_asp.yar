rule elmaliseker_asp {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file elmaliseker.asp.txt"
    family = "None"
    hacker = "None"
    hash = "b32d1730d23a660fd6aa8e60c3dc549f"
    judge = "unknown"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "if Int((1-0+1)*Rnd+0)=0 then makeEmail=makeText(8) & \"@\" & makeText(8) & \".\""
    $s1 = "<form name=frmCMD method=post action=\"<%=gURL%>\">"
    $s2 = "dim zombie_array,special_array"
    $s3 = "http://vnhacker.org"
  condition:
    1 of them
}