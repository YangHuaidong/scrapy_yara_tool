rule APT30_Sample_18 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file b2138a57f723326eda5a26d2dec56851"
    family = "None"
    hacker = "None"
    hash = "355436a16d7a2eba8a284b63bb252a8bb1644751"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "w.km-nyc.com" fullword ascii
    $s1 = "tscv.exe" fullword ascii
    $s2 = "Exit/app.htm" ascii
    $s3 = "UBD:\\D" ascii
    $s4 = "LastError" ascii
    $s5 = "MicrosoftHaveAck" ascii
    $s7 = "HHOSTR" ascii
    $s20 = "XPL0RE." ascii
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}