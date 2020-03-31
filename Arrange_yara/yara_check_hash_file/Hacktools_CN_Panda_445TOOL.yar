rule Hacktools_CN_Panda_445TOOL {
  meta:
    author = Spider
    comment = None
    date = 17.11.14
    description = Disclosed hacktool set - file 445TOOL.rar
    family = 445TOOL
    hacker = None
    hash = 92050ba43029f914696289598cf3b18e34457a11
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 60
    threatname = Hacktools[CN]/Panda.445TOOL
    threattype = CN
  strings:
    $s0 = "scan.bat" fullword ascii
    $s1 = "Http.exe" fullword ascii
    $s2 = "GOGOGO.bat" fullword ascii
    $s3 = "ip.txt" fullword ascii
  condition:
    all of them
}