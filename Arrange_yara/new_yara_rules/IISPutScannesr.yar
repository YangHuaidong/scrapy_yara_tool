rule IISPutScannesr {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file IISPutScannesr.exe"
    family = "None"
    hacker = "None"
    hash = "2dd8fee20df47fd4eed5a354817ce837752f6ae9"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "yoda & M.o.D." ascii
    $s2 = "-> come.to/f2f **************" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 500KB and all of them
}