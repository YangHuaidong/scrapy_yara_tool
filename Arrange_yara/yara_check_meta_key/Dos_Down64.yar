rule Dos_Down64 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file Down64.exe"
    family = "None"
    hacker = "None"
    hash = "43e455e43b49b953e17a5b885ffdcdf8b6b23226"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "C:\\Windows\\Temp\\Down.txt" fullword wide
    $s2 = "C:\\Windows\\Temp\\Cmd.txt" fullword wide
    $s3 = "C:\\Windows\\Temp\\" fullword wide
    $s4 = "ProcessXElement" fullword ascii
    $s8 = "down.exe" fullword wide
    $s20 = "set_Timer1" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 150KB and all of them
}