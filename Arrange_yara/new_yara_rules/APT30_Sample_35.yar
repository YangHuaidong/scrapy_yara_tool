rule APT30_Sample_35 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file 414854a9b40f7757ed7bfc6a1b01250f"
    family = "None"
    hacker = "None"
    hash = "df48a7cd6c4a8f78f5847bad3776abc0458499a6"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "WhBoyIEXPLORE.EXE.exe" fullword ascii
    $s5 = "Startup>A" fullword ascii
    $s18 = "olhelp32Snapshot" fullword ascii
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}