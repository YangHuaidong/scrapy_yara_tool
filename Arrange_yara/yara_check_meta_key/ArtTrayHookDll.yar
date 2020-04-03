rule ArtTrayHookDll {
  meta:
    author = "Spider"
    comment = "None"
    date = "23.11.14"
    description = "Disclosed hacktool set (old stuff) - file ArtTrayHookDll.dll"
    family = "None"
    hacker = "None"
    hash = "4867214a3d96095d14aa8575f0adbb81a9381e6c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "ArtTrayHookDll.dll" fullword ascii
    $s7 = "?TerminateHook@@YAXXZ" fullword ascii
  condition:
    all of them
}