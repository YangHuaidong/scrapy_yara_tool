rule datPcShare {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file datPcShare.exe"
    family = "None"
    hacker = "None"
    hash = "87acb649ab0d33c62e27ea83241caa43144fc1c4"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "PcShare.EXE" fullword wide
    $s2 = "MZKERNEL32.DLL" fullword ascii
    $s3 = "PcShare" fullword wide
    $s4 = "QQ:4564405" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 500KB and all of them
}