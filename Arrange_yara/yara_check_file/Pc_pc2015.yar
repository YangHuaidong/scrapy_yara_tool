rule Pc_pc2015 {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file pc2015.exe
    family = None
    hacker = None
    hash = de4f098611ac9eece91b079050b2d0b23afe0bcb
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = Pc[pc2015
    threattype = pc2015.yar
  strings:
    $s0 = "\\svchost.exe" fullword ascii
    $s1 = "LON\\OD\\O-\\O)\\O%\\O!\\O=\\O9\\O5\\O1\\O" fullword ascii
    $s8 = "%s%08x.001" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 309KB and all of them
}