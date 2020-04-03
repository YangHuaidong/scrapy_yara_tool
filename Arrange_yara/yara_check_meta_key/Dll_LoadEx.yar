rule Dll_LoadEx {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file Dll_LoadEx.exe"
    family = "None"
    hacker = "None"
    hash = "213d9d0afb22fe723ff570cf69ff8cdb33ada150"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "WiNrOOt@126.com" fullword wide
    $s1 = "Dll_LoadEx.EXE" fullword wide
    $s3 = "You Already Loaded This DLL ! :(" fullword ascii
    $s10 = "Dll_LoadEx Microsoft " fullword wide
    $s17 = "Can't Load This Dll ! :(" fullword ascii
    $s18 = "WiNrOOt" fullword wide
    $s20 = " Dll_LoadEx(&A)..." fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 120KB and 3 of them
}