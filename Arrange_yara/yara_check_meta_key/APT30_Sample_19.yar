rule APT30_Sample_19 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file 5d4f2871fd1818527ebd65b0ff930a77"
    family = "None"
    hacker = "None"
    hash = "cfa438449715b61bffa20130df8af778ef011e15"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "C:\\Program Files\\Common Files\\System\\wab32" fullword ascii
    $s1 = "%s,Volume:%s,Type:%s,TotalSize:%uMB,FreeSize:%uMB" fullword ascii
    $s2 = "\\TEMP\\" fullword ascii
    $s3 = "\\Temporary Internet Files\\" fullword ascii
    $s5 = "%s TotalSize:%u Bytes" fullword ascii
    $s6 = "This Disk Maybe a Encrypted Flash Disk!" fullword ascii
    $s7 = "User:%-32s" fullword ascii
    $s8 = "\\Desktop\\" fullword ascii
    $s9 = "%s.%u_%u" fullword ascii
    $s10 = "Nick:%-32s" fullword ascii
    $s11 = "E-mail:%-32s" fullword ascii
    $s13 = "%04u-%02u-%02u %02u:%02u:%02u" fullword ascii
    $s14 = "Type:%-8s" fullword ascii
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and 8 of them
}