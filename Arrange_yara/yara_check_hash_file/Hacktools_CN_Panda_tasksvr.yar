rule Hacktools_CN_Panda_tasksvr {
  meta:
    author = Spider
    comment = None
    date = 17.11.14
    description = Disclosed hacktool set - file tasksvr.exe
    family = tasksvr
    hacker = None
    hash = a73fc74086c8bb583b1e3dcfd326e7a383007dc0
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 60
    threatname = Hacktools[CN]/Panda.tasksvr
    threattype = CN
  strings:
    $s2 = "Consys21.dll" fullword ascii
    $s4 = "360EntCall.exe" fullword wide
    $s15 = "Beijing1" fullword ascii
  condition:
    all of them
}