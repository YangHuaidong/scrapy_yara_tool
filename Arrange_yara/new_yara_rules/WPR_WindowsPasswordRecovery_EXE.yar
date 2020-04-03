rule WPR_WindowsPasswordRecovery_EXE {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-03-15"
    description = "Windows Password Recovery - file wpr.exe"
    family = "None"
    hacker = "None"
    hash1 = "c1c64cba5c8e14a1ab8e9dd28828d036581584e66ed111455d6b4737fb807783"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "UuPipe" fullword ascii
    $x2 = "dbadllgl" fullword ascii
    $x3 = "UkVHSVNUUlkgTU9O" fullword ascii /* base64 encoded string 'REGISTRY MON' */
    $x4 = "RklMRSBNT05JVE9SIC0gU1l" fullword ascii /* base64 encoded string 'FILE MONITOR - SY' */
    $s1 = "WPR.exe" fullword wide
    $s2 = "Windows Password Recovery" fullword wide
    $op0 = { 5f df 27 17 89 } /* Opcode */
    $op1 = { 5f 00 00 f2 e5 cb 97 } /* Opcode */
    $op2 = { e8 ed 00 f0 cc e4 00 a0 17 } /* Opcode */
  condition:
    uint16(0) == 0x5a4d and
    filesize < 20000KB and
    1 of ($x*) or
    all of ($s*) or
    all of ($op*)
}