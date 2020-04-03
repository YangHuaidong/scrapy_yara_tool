rule Microcin_Sample_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-09-26"
    description = "Malware sample mentioned in Microcin technical report by Kaspersky"
    family = "None"
    hacker = "None"
    hash1 = "4f74a3b67c5ed6f38f08786f1601214412249fe128f12c51525135710d681e1d"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "C:\\Users\\Lenovo\\Desktop\\test\\Release\\test.pdb" fullword ascii
    $s2 = "test, Version 1.0" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}