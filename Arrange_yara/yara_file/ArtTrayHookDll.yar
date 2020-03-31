rule ArtTrayHookDll {
   meta:
      description = "Disclosed hacktool set (old stuff) - file ArtTrayHookDll.dll"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      date = "23.11.14"
      score = 60
      hash = "4867214a3d96095d14aa8575f0adbb81a9381e6c"
   strings:
      $s0 = "ArtTrayHookDll.dll" fullword ascii
      $s7 = "?TerminateHook@@YAXXZ" fullword ascii
   condition:
      all of them
}