rule Txt_shell {
  meta:
    author = Spider
    comment = None
    date = 2015-06-14
    description = Chinese Hacktool Set - Webshells - file shell.c
    family = None
    hacker = None
    hash = 8342b634636ef8b3235db0600a63cc0ce1c06b62
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = Txt[shell
    threattype = shell.yar
  strings:
    $s1 = "printf(\"Could not connect to remote shell!\\n\");" fullword ascii
    $s2 = "printf(\"Usage: %s <reflect ip> <port>\\n\", prog);" fullword ascii
    $s3 = "execl(shell,\"/bin/sh\",(char *)0);" fullword ascii
    $s4 = "char shell[]=\"/bin/sh\";" fullword ascii
    $s5 = "connect back door\\n\\n\");" fullword ascii
  condition:
    filesize < 2KB and 2 of them
}