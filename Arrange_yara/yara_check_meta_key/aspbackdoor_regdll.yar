rule aspbackdoor_regdll {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file regdll.asp"
    family = "None"
    hacker = "None"
    hash = "5c5e16a00bcb1437bfe519b707e0f5c5f63a488d"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "exitcode = oShell.Run(\"c:\\WINNT\\system32\\regsvr32.exe /u/s \" & strFile, 0, " ascii
    $s3 = "oShell.Run \"c:\\WINNT\\system32\\regsvr32.exe /u/s \" & strFile, 0, False" fullword ascii
    $s4 = "EchoB(\"regsvr32.exe exitcode = \" & exitcode)" fullword ascii
    $s5 = "Public Property Get oFS()" fullword ascii
  condition:
    all of them
}