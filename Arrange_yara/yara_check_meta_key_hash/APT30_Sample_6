rule APT30_Sample_6 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file ee1b23c97f809151805792f8778ead74"
    family = "None"
    hacker = "None"
    hash = "00e69b059ad6b51b76bc476a115325449d10b4c0"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "GreateProcessA" fullword ascii
    $s1 = "Ternel32.dll" fullword ascii
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}