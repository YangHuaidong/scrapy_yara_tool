rule APT30_Sample_16 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file 37e568bed4ae057e548439dc811b4d3a"
    family = "None"
    hacker = "None"
    hash = "066d06ac08b48d3382d46bbeda6ad411b6d6130e"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "\\Temp1020.txt" fullword ascii
    $s1 = "cmcbqyjs" fullword ascii
    $s2 = "SPVSWh\\" fullword ascii
    $s4 = "PSShxw@" fullword ascii
    $s5 = "VWhHw@" fullword ascii
    $s7 = "SVWhHw@" fullword ascii
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}