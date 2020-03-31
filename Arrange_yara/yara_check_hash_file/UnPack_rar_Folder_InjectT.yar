rule UnPack_rar_Folder_InjectT {
  meta:
    author = Spider
    comment = None
    date = 23.11.14
    description = Disclosed hacktool set (old stuff) - file InjectT.exe
    family = InjectT
    hacker = None
    hash = 80f39e77d4a34ecc6621ae0f4d5be7563ab27ea6
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    score = 60
    threatname = UnPack[rar]/Folder.InjectT
    threattype = rar
  strings:
    $s0 = "%s -Install                          -->To Install The Service" fullword ascii
    $s1 = "Explorer.exe" fullword ascii
    $s2 = "%s -Start                            -->To Start The Service" fullword ascii
    $s3 = "%s -Stop                             -->To Stop The Service" fullword ascii
    $s4 = "The Port Is Out Of Range" fullword ascii
    $s7 = "Fail To Set The Port" fullword ascii
    $s11 = "\\psapi.dll" fullword ascii
    $s20 = "TInject.Dll" fullword ascii
    $x1 = "Software\\Microsoft\\Internet Explorer\\WinEggDropShell" fullword ascii
    $x2 = "injectt.exe" fullword ascii
  condition:
    ( 1 of ($x*) ) and ( 3 of ($s*) )
}