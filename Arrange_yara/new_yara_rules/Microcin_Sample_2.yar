rule Microcin_Sample_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-09-26"
    description = "Malware sample mentioned in Microcin technical report by Kaspersky"
    family = "None"
    hacker = "None"
    hash1 = "8a7d04229722539f2480270851184d75b26c375a77b468d8cbad6dbdb0c99271"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://securelist.com/files/2017/09/Microcin_Technical-PDF_eng_final.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "[Pause]" fullword ascii
    $s7 = "IconCache_%02d%02d%02d%02d%02d" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}