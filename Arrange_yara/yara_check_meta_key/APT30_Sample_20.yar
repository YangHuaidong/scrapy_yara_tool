rule APT30_Sample_20 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file 5ae51243647b7d03a5cb20dccbc0d561"
    family = "None"
    hacker = "None"
    hash = "b1c37632e604a5d1f430c9351f87eb9e8ea911c0"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "dizhi.gif" fullword ascii
    $s2 = "Mozilla/u" ascii
    $s3 = "XicrosoftHaveAck" ascii
    $s4 = "flyeagles" ascii
    $s10 = "iexplore." ascii
    $s13 = "WindowsGV" fullword ascii
    $s16 = "CatePipe" fullword ascii
    $s17 = "'QWERTY:/webpage3" fullword ascii
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}