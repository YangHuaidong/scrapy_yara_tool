rule Hacktools_CN_Panda_tasksvr {
  meta:
    author = "Spider"
    comment = "None"
    date = "17.11.14"
    description = "Disclosed hacktool set - file tasksvr.exe"
    family = "None"
    hacker = "None"
    hash = "a73fc74086c8bb583b1e3dcfd326e7a383007dc0"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "Consys21.dll" fullword ascii
    $s4 = "360EntCall.exe" fullword wide
    $s15 = "Beijing1" fullword ascii
  condition:
    all of them
}