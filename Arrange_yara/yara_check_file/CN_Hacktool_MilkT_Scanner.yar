rule CN_Hacktool_MilkT_Scanner {
  meta:
    author = Spider
    comment = None
    date = 12.10.2014
    description = Detects a chinese Portscanner named MilkT
    family = Scanner
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 60
    threatname = CN[Hacktool]/MilkT.Scanner
    threattype = Hacktool
  strings:
    $s0 = "Bf **************" ascii fullword
    $s1 = "forming Time: %d/" ascii
    $s2 = "KERNEL32.DLL" ascii fullword
    $s3 = "CRTDLL.DLL" ascii fullword
    $s4 = "WS2_32.DLL" ascii fullword
    $s5 = "GetProcAddress" ascii fullword
    $s6 = "atoi" ascii fullword
  condition:
    all of them
}