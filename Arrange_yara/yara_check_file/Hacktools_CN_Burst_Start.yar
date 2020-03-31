rule Hacktools_CN_Burst_Start {
  meta:
    author = Spider
    comment = None
    date = 17.11.14
    description = Disclosed hacktool set - file Start.bat - DoS tool
    family = Start
    hacker = None
    hash = 75d194d53ccc37a68286d246f2a84af6b070e30c
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 60
    threatname = Hacktools[CN]/Burst.Start
    threattype = CN
  strings:
    $s0 = "for /f \"eol= tokens=1,2 delims= \" %%i in (ip.txt) do (" fullword ascii
    $s1 = "Blast.bat /r 600" fullword ascii
    $s2 = "Blast.bat /l Blast.bat" fullword ascii
    $s3 = "Blast.bat /c 600" fullword ascii
    $s4 = "start Clear.bat" fullword ascii
    $s5 = "del Result.txt" fullword ascii
    $s6 = "s syn %%i %%j 3306 /save" fullword ascii
    $s7 = "start Thecard.bat" fullword ascii
    $s10 = "setlocal enabledelayedexpansion" fullword ascii
  condition:
    5 of them
}