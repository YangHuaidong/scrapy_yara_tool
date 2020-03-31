rule CN_Honker_SqlMap_Python_Run {
  meta:
    author = Spider
    comment = None
    date = 2015-06-23
    description = Sample from CN Honker Pentest Toolset - file Run.exe
    family = Python
    hacker = None
    hash = a51479a1c589f17c77d22f6cf90b97011c33145f
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = Disclosed CN Honker Pentest Toolset
    score = 70
    threatname = CN[Honker]/SqlMap.Python.Run
    threattype = Honker
  strings:
    $s1 = ".\\Run.log" fullword ascii
    $s2 = "[root@Hacker~]# Sqlmap " fullword ascii
    $s3 = "%sSqlmap %s" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 30KB and all of them
}