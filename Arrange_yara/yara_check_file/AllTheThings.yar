rule AllTheThings {
   meta:
      description = "Detects AllTheThings"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "https://github.com/subTee/AllTheThings"
      date = "2017-07-27"
      hash1 = "5a0e9a9ce00d843ea95bd5333b6ab50cc5b1dbea648cc819cfe48482513ce842"
   strings:
      $x1 = "\\obj\\Debug\\AllTheThings.pdb" fullword ascii
      $x2 = "AllTheThings.exe" fullword wide
      $x3 = "\\AllTheThings.dll" fullword ascii
      $x4 = "Hello From Main...I Don't Do Anything" fullword wide
      $x5 = "I am a basic COM Object" fullword wide
      $x6 = "I shouldn't really execute either." fullword wide
   condition:
      ( uint16(0) == 0x5a4d and filesize < 50KB and 1 of them )
}