rule cmdjsp_jsp {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file cmdjsp.jsp.txt"
    family = "None"
    hacker = "None"
    hash = "b815611cc39f17f05a73444d699341d4"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "// note that linux = cmd and windows = \"cmd.exe /c + cmd\" " fullword
    $s1 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);" fullword
    $s2 = "cmdjsp.jsp"
    $s3 = "michaeldaw.org" fullword
  condition:
    2 of them
}