rule APT30_Sample_17 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file 23813c5bf6a7af322b40bd2fd94bd42e"
    family = "None"
    hacker = "None"
    hash = "c3aa52ff1d19e8fc6704777caf7c5bd120056845"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Nkfvtyvn}]ty}ztU" fullword ascii
    $s4 = "IEXPL0RE" fullword ascii
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}