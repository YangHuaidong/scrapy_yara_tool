rule APT30_Sample_14 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file 6f931c15789d234881be8ae8ccfe33f4"
    family = "None"
    hacker = "None"
    hash = "b0740175d20eab79a5d62cdbe0ee1a89212a8472"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "AdobeReader.exe" fullword wide
    $s4 = "10.1.7.27" fullword wide
    $s5 = "Copyright 1984-2012 Adobe Systems Incorporated and its licensors. All ri" wide
    $s8 = "Adobe Reader" fullword wide
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}