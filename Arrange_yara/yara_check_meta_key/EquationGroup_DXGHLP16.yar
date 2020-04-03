rule EquationGroup_DXGHLP16 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-13"
    description = "EquationGroup Malware - file DXGHLP16.SYS"
    family = "None"
    hacker = "None"
    hash1 = "fcfb56fa79d2383d34c471ef439314edc2239d632a880aa2de3cea430f6b5665"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/tcSoiJ"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "DXGHLP16.SYS" fullword wide
    $s2 = "P16.SYS" fullword ascii
    $s3 = "\\Registry\\User\\CurrentUser\\" fullword wide
    $s4 = "\\DosDevices\\%ws" fullword wide
    $s5 = "\\Device\\%ws_%ws" fullword wide
    $s6 = "ct@SYS\\DXGHLP16.dbg" fullword ascii
    $s7 = "%ws%03d%ws%wZ" fullword wide
    $s8 = "TCP/IP driver" fullword wide
    $s9 = "\\Device\\%ws" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}