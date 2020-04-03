rule lsremora {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-09-08"
    description = "Detects a tool used by APT groups"
    family = "None"
    hacker = "None"
    hash1 = "efa66f6391ec471ca52cd053159c8a8778f11f921da14e6daf76387f8c9afcd5"
    hash2 = "e0327c1218fd3723e20acc780e20135f41abca35c35e0f97f7eccac265f4f44e"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://goo.gl/igxLyF"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Target: Failed to load primary SAM functions." fullword ascii
    $x2 = "lsremora64.dll" fullword ascii
    $x3 = "PwDumpError:999999" fullword wide
    $x4 = "PwDumpError" fullword wide
    $x5 = "lsremora.dll" fullword ascii
    $s1 = ":\\\\.\\pipe\\%s" fullword ascii
    $s2 = "x%s_history_%d:%d" fullword wide
    $s3 = "Using pipe %s" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and 1 of ($x*) ) or ( 3 of them )
}