rule portscanner {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-13"
    description = "Chinese Hacktool Set - file portscanner.exe"
    family = "None"
    hacker = "None"
    hash = "1de367d503fdaaeee30e8ad7c100dd1e320858a4"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://tools.zjqhr.com/"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "PortListfNo" fullword ascii
    $s1 = ".533.net" fullword ascii
    $s2 = "CRTDLL.DLL" fullword ascii
    $s3 = "exitfc" fullword ascii
  condition:
    uint16(0) == 0x5a4d and filesize < 25KB and all of them
}