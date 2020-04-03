rule Txt_jspcmd {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-14"
    description = "Chinese Hacktool Set - Webshells - file jspcmd.txt"
    family = "None"
    hacker = "None"
    hash = "1d4e789031b15adde89a4628afc759859e53e353"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "if(\"1752393\".equals(request.getParameter(\"Confpwd\"))){" fullword ascii
    $s4 = "out.print(\"Hi,Man 2015\");" fullword ascii
  condition:
    filesize < 1KB and 1 of them
}