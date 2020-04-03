rule APT30_Sample_15 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file e26a2afaaddfb09d9ede505c6f1cc4e3"
    family = "None"
    hacker = "None"
    hash = "7a8576804a2bbe4e5d05d1718f90b6a4332df027"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "\\Windo" ascii
    $s2 = "HHOSTR"  ascii
    $s3 = "Softwa]\\Mic" ascii
    $s4 = "Startup'T" fullword ascii
    $s17 = "help32Snapshot0L" fullword ascii
    $s18 = "TimUmoveH" ascii
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}