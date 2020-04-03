rule APT30_Generic_8 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015/04/13"
    description = "FireEye APT30 Report Sample"
    family = "None"
    hacker = "None"
    hash0 = "b47e20ac5889700438dc241f28f4e224070810d2"
    hash1 = "a9a50673ac000a313f3ddba55d63d9773b9f4143"
    hash2 = "ac96d7f5957aef09bd983465c497de24c6d17a92"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Windows NT4.0" fullword
    $s1 = "Windows NT3.51" fullword
    $s2 = "%d;%d;%d;%ld;%ld;%ld;" fullword
    $s3 = "%s %d.%d Build%d %s" fullword
    $s4 = "MSAFD Tcpip [TCP/IP]" fullword
    $s5 = "SQSRSS" fullword
    $s8 = "WM_COMP" fullword
    $s9 = "WM_MBU" fullword
    $s11 = "WM_GRID" fullword
    $s12 = "WM_RBU" fullword
  condition:
    filesize < 250KB and uint16(0) == 0x5A4D and all of them
}