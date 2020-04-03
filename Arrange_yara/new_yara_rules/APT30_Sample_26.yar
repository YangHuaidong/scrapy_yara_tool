rule APT30_Sample_26 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file 428fc53c84e921ac518e54a5d055f54a"
    family = "None"
    hacker = "None"
    hash = "e26588113417bf68cb0c479638c9cd99a48e846d"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "forcegue" fullword ascii
    $s3 = "Windows\\Cur" fullword ascii
    $s4 = "System Id" fullword ascii
    $s5 = "Software\\Mic" fullword ascii
    $s6 = "utiBy0ToWideCh&$a" fullword ascii
    $s10 = "ModuleH" fullword ascii
    $s15 = "PeekNamed6G" fullword ascii
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}