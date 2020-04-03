rule APT30_Generic_K {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file b5a343d11e1f7340de99118ce9fc1bbb"
    family = "None"
    hacker = "None"
    hash = "142bc01ad412799a7f9ffed994069fecbd5a2f93"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "Maybe a Encrypted Flash" fullword ascii
    $s0 = "C:\\Program Files\\Common Files\\System\\wab32" fullword ascii
    $s1 = "\\TEMP\\" fullword ascii
    $s2 = "\\Temporary Internet Files\\" fullword ascii
    $s5 = "%s Size:%u Bytes" fullword ascii
    $s7 = "$.DATA$" fullword ascii
    $s10 = "? Size:%u By s" fullword ascii
    $s12 = "Maybe a Encrypted Flash" fullword ascii
    $s14 = "Name:%-32s" fullword ascii
    $s15 = "NickName:%-32s" fullword ascii
    $s19 = "Email:%-32s" fullword ascii
    $s21 = "C:\\Prog" ascii
    $s22 = "$LDDATA$" ascii
    $s31 = "Copy File %s OK!" fullword ascii
    $s32 = "%s Space:%uM,FreeSpace:%uM" fullword ascii
    $s34 = "open=%s" fullword ascii
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and ( all of ($x*) and 3 of ($s*) )
}