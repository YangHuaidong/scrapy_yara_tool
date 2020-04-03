rule SQLCracker {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file SQLCracker.exe"
    family = "None"
    hacker = "None"
    hash = "1aa5755da1a9b050c4c49fc5c58fa133b8380410"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "msvbvm60.dll" fullword ascii /* reversed goodware string 'lld.06mvbvsm' */
    $s1 = "_CIcos" fullword ascii
    $s2 = "kernel32.dll" fullword ascii
    $s3 = "cKmhV" fullword ascii
    $s4 = "080404B0" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 125KB and all of them
}