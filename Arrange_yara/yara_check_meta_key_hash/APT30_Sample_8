rule APT30_Sample_8 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file 44b98f22155f420af4528d17bb4a5ec8"
    family = "None"
    hacker = "None"
    hash = "9531e21652143b8b129ab8c023dc05fef2a17cc3"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "ateProcessA" ascii
    $s1 = "Ternel32.dllFQ" fullword ascii
    $s2 = "StartupInfoAModuleHand" fullword ascii
    $s3 = "OpenMutex" fullword ascii
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}