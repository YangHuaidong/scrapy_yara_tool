rule APT30_Sample_23 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file a5ca2c5b4d8c0c1bc93570ed13dcab1a"
    family = "None"
    hacker = "None"
    hash = "9865e24aadb4480bd3c182e50e0e53316546fc01"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "hostid" ascii
    $s1 = "\\Window" ascii
    $s2 = "%u:%u%s" fullword ascii
    $s5 = "S2tware\\Mic" ascii
    $s6 = "la/4.0 (compa" ascii
    $s7 = "NameACKernel" fullword ascii
    $s12 = "ToWideChc[lo" fullword ascii
    $s14 = "help32SnapshotfL" ascii
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}