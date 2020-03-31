rule CN_Hacktool_S_EXE_Portscanner {
  meta:
    author = Spider
    comment = None
    date = 12.10.2014
    description = Detects a chinese Portscanner named s.exe
    family = EXE
    hacker = None
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 70
    threatname = CN[Hacktool]/S.EXE.Portscanner
    threattype = Hacktool
  strings:
    $s0 = "\\Result.txt" fullword ascii
    $s1 = "By:ZT QQ:376789051" fullword ascii
    $s2 = "(http://www.eyuyan.com)" fullword wide
  condition:
    all of them
}