rule APT30_Sample_29 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file 1b81b80ff0edf57da2440456d516cc90"
    family = "None"
    hacker = "None"
    hash = "44492c53715d7c79895904543843a321491cb23a"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "LSSAS.exe" fullword ascii
    $s1 = "Software\\Microsoft\\FlashDiskInf" fullword ascii
    $s2 = ".petite" fullword ascii
    $s3 = "MicrosoftFlashExit" fullword ascii
    $s4 = "MicrosoftFlashHaveExit" fullword ascii
    $s5 = "MicrosoftFlashHaveAck" fullword ascii
    $s6 = "\\driver32" fullword ascii
    $s7 = "MicrosoftFlashZJ" fullword ascii
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}