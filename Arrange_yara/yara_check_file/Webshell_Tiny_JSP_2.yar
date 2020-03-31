rule Webshell_Tiny_JSP_2 {
  meta:
    author = Spider
    comment = None
    date = 2015-12-05
    description = Detects a tiny webshell - chine chopper
    family = 2
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 100
    threatname = Webshell[Tiny]/JSP.2
    threattype = Tiny
  strings:
    $s1 = "<%eval(Request(" nocase
  condition:
    uint16(0) == 0x253c and filesize < 40 and all of them
}