rule APT30_Sample_25 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file c4c068200ad8033a0f0cf28507b51842"
    family = "None"
    hacker = "None"
    hash = "44a21c8b3147fabc668fee968b62783aa9d90351"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "C:\\WINDOWS" fullword ascii
    $s2 = "aragua" fullword ascii
    $s4 = "\\driver32\\7$" fullword ascii
    $s8 = "System V" fullword ascii
    $s9 = "Compu~r" fullword ascii
    $s10 = "PROGRAM L" fullword ascii
    $s18 = "GPRTMAX" fullword ascii
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}