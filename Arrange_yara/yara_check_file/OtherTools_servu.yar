rule OtherTools_servu {
  meta:
    author = Spider
    comment = None
    date = 2015-06-13
    description = Chinese Hacktool Set - file svu.exe
    family = None
    hacker = None
    hash = 5c64e6879a9746a0d65226706e0edc7a
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = http://tools.zjqhr.com/
    threatname = OtherTools[servu
    threattype = servu.yar
  strings:
    $s0 = "MZKERNEL32.DLL" fullword ascii
    $s1 = "UpackByDwing@" fullword ascii
    $s2 = "GetProcAddress" fullword ascii
    $s3 = "WriteFile" fullword ascii
  condition:
    uint32(0) == 0x454b5a4d and $s0 at 0 and filesize < 50KB and all of them
}