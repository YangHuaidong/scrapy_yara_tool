rule APT30_Sample_31 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file d8e68db503f4155ed1aeba95d1f5e3e4"
    family = "None"
    hacker = "None"
    hash = "8b4271167655787be1988574446125eae5043aca"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "\\ZJRsv.tem" fullword ascii
    $s1 = "forceguest" fullword ascii
    $s4 = "\\$NtUninstallKB570317$" fullword ascii
    $s8 = "[Can'tGetIP]" fullword ascii
    $s14 = "QWERTY:,`/" fullword ascii
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}