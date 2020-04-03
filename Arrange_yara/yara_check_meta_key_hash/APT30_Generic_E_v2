rule APT30_Generic_E_v2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file 71f25831681c19ea17b2f2a84a41bbfb"
    family = "None"
    hacker = "None"
    hash = "eca53a9f6251ddf438508b28d8a483f91b99a3fd"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Nkfvtyvn}duf_Z}{Ys" fullword ascii
    $s1 = "Nkfvtyvn}*Zrswru1i" fullword ascii
    $s2 = "Nkfvtyvn}duf_Z}{V" fullword ascii
    $s3 = "Nkfvtyvn}*ZrswrumT\\b" fullword ascii
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}