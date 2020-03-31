rule webshell_jsp_cmdjsp_2 {
  meta:
    author = Spider
    comment = None
    date = 2014/01/28
    description = Web Shell - file cmdjsp.jsp
    family = 2
    hacker = None
    hash = 1b5ae3649f03784e2a5073fa4d160c8b
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = webshell[jsp]/cmdjsp.2
    threattype = jsp
  strings:
    $s0 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);" fullword
    $s4 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword
  condition:
    all of them
}