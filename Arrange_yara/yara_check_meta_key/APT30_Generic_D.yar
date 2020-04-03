rule APT30_Generic_D {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file 597805832d45d522c4882f21db800ecf"
    family = "None"
    hacker = "None"
    hash1 = "35dfb55f419f476a54241f46e624a1a4"
    hash2 = "4fffcbdd4804f6952e0daf2d67507946"
    hash3 = "597805832d45d522c4882f21db800ecf"
    hash4 = "6bd422d56e85024e67cc12207e330984"
    hash5 = "82e13f3031130bd9d567c46a9c71ef2b"
    hash6 = "b79d87ff6de654130da95c73f66c15fa"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Windows Security Service Feedback" fullword wide
    $s1 = "wssfmgr.exe" fullword wide
    $s2 = "\\rb.htm" fullword ascii
    $s3 = "rb.htm" fullword ascii
    $s4 = "cook5" ascii
    $s5 = "5, 4, 2600, 0" fullword wide
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}