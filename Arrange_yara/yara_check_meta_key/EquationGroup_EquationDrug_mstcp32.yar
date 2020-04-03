rule EquationGroup_EquationDrug_mstcp32 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-13"
    description = "EquationGroup Malware - file mstcp32.sys"
    family = "None"
    hacker = "None"
    hash1 = "26215bc56dc31d2466d72f1f4e1b6388e62606e9949bc41c28968fcb9a9d60a6"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/tcSoiJ"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "mstcp32.sys" fullword wide
    $s2 = "p32.sys" fullword ascii
    $s3 = "\\Registry\\User\\CurrentUser\\" fullword wide
    $s4 = "\\DosDevices\\%ws" fullword wide
    $s5 = "\\Device\\%ws_%ws" fullword wide
    $s6 = "sys\\mstcp32.dbg" fullword ascii
    $s7 = "%ws%03d%ws%wZ" fullword wide
    $s8 = "TCP/IP driver" fullword wide
    $s9 = "\\Device\\%ws" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and 7 of them ) or ( all of them )
}