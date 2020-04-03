rule APT30_Sample_4 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file 6ba315275561d99b1eb8fc614ff0b2b3"
    family = "None"
    hacker = "None"
    hash = "75367d8b506031df5923c2d8d7f1b9f643a123cd"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "GetStartupIn" ascii
    $s1 = "enMutex" ascii
    $s2 = "tpsvimi" ascii
    $s3 = "reateProcesy" ascii
    $s5 = "FreeLibr1y*S" ascii
    $s6 = "foAModuleHand" ascii
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}