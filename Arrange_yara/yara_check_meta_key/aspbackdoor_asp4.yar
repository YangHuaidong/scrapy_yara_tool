rule aspbackdoor_asp4 {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file asp4.txt"
    family = "None"
    hacker = "None"
    hash = "faf991664fd82a8755feb65334e5130f791baa8c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "system.dll" fullword ascii
    $s2 = "set sys=server.CreateObject (\"system.contral\") " fullword ascii
    $s3 = "Public Function reboot(atype As Variant)" fullword ascii
    $s4 = "t& = ExitWindowsEx(1, atype)" ascii
    $s5 = "atype=request(\"atype\") " fullword ascii
    $s7 = "AceiveX dll" fullword ascii
    $s8 = "Declare Function ExitWindowsEx Lib \"user32\" (ByVal uFlags As Long, ByVal " ascii
    $s10 = "sys.reboot(atype)" fullword ascii
  condition:
    all of them
}