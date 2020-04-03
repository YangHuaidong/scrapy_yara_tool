rule WinEggDropShellFinal_zip_Folder_InjectT {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file InjectT.exe"
    family = "None"
    hacker = "None"
    hash = "516e80e4a25660954de8c12313e2d7642bdb79dd"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Packed by exe32pack" ascii
    $s1 = "2TInject.Dll" fullword ascii
    $s2 = "Windows Services" fullword ascii
    $s3 = "Findrst6" fullword ascii
    $s4 = "Press Any Key To Continue......" fullword ascii
  condition:
    all of them
}