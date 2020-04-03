rule Tools_2014 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file 2014.jsp"
    family = "None"
    hacker = "None"
    hash = "74518faf08637c53095697071db09d34dbe8d676"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "((Invoker) ins.get(\"login\")).invoke(request, response," fullword ascii
    $s4 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
    $s5 = ": \"c:\\\\windows\\\\system32\\\\cmd.exe\")" fullword ascii
  condition:
    filesize < 715KB and all of them
}