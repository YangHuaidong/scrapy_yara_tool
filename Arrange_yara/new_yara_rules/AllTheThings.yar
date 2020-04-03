rule AllTheThings {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-07-27"
    description = "Detects AllTheThings"
    family = "None"
    hacker = "None"
    hash1 = "5a0e9a9ce00d843ea95bd5333b6ab50cc5b1dbea648cc819cfe48482513ce842"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/subTee/AllTheThings"
    threatname = "None"
    threattype = "None"
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