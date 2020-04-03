rule Hacktools_CN_JoHor_Posts_Killer {
  meta:
    author = "Spider"
    comment = "None"
    date = "17.11.14"
    description = "Disclosed hacktool set - file JoHor_Posts_Killer.exe"
    family = "None"
    hacker = "None"
    hash = "d157f9a76f9d72dba020887d7b861a05f2e56b6a"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Multithreading Posts_Send Killer" fullword ascii
    $s3 = "GET [Access Point] HTTP/1.1" fullword ascii
    $s6 = "The program's need files was not exist!" fullword ascii
    $s7 = "JoHor_Posts_Killer" fullword wide
    $s8 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)" fullword ascii
    $s10 = "  ( /s ) :" fullword ascii
    $s11 = "forms.vbp" fullword ascii
    $s12 = "forms.vcp" fullword ascii
    $s13 = "Software\\FlySky\\E\\Install" fullword ascii
  condition:
    5 of them
}