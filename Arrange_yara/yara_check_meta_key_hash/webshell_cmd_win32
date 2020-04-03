rule webshell_cmd_win32 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file cmd_win32.jsp"
    family = "None"
    hacker = "None"
    hash = "cc4d4d6cc9a25984aa9a7583c7def174"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /c \" + request.getParam"
    $s1 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">" fullword
  condition:
    2 of them
}