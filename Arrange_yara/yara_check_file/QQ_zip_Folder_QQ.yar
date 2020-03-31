rule QQ_zip_Folder_QQ {
  meta:
    author = Spider
    comment = None
    date = 23.11.14
    description = Disclosed hacktool set (old stuff) - file QQ.exe
    family = QQ
    hacker = None
    hash = 9f8e3f40f1ac8c1fa15a6621b49413d815f46cfb
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 60
    threatname = QQ[zip]/Folder.QQ
    threattype = zip
  strings:
    $s0 = "EMAIL:haoq@neusoft.com" fullword wide
    $s1 = "EMAIL:haoq@neusoft.com" fullword wide
    $s4 = "QQ2000b.exe" fullword wide
    $s5 = "haoq@neusoft.com" fullword ascii
    $s9 = "QQ2000b.exe" fullword ascii
    $s10 = "\\qq2000b.exe" fullword ascii
    $s12 = "WINDSHELL STUDIO[WINDSHELL " fullword wide
    $s17 = "SOFTWARE\\HAOQIANG\\" fullword ascii
  condition:
    5 of them
}