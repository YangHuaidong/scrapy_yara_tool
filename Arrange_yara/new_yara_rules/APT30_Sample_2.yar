rule APT30_Sample_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample - file c4dec6d69d8035d481e4f2c86f580e81"
    family = "None"
    hacker = "None"
    hash = "0359ffbef6a752ee1a54447b26e272f4a5a35167"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "ForZRLnkWordDlg.EXE" fullword wide
    $s1 = "ForZRLnkWordDlg Microsoft " fullword wide
    $s9 = "ForZRLnkWordDlg 1.0 " fullword wide
    $s11 = "ForZRLnkWordDlg" fullword wide
    $s12 = " (C) 2011" fullword wide
  condition:
    filesize < 100KB and uint16(0) == 0x5A4D and all of them
}