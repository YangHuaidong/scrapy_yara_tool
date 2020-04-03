rule CN_Tools_pc {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file pc.exe"
    family = "None"
    hacker = "None"
    hash = "5cf8caba170ec461c44394f4058669d225a94285"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "\\svchost.exe" fullword ascii
    $s2 = "%s%08x.001" fullword ascii
    $s3 = "Qy001Service" fullword ascii
    $s4 = "/.MIKY" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 300KB and all of them
}