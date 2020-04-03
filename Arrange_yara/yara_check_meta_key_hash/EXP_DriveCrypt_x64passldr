rule EXP_DriveCrypt_x64passldr {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-08-21"
    description = "Detects DriveCrypt exploit"
    family = "None"
    hacker = "None"
    hash1 = "c828304c83619e2cb9dab80305e5286aba91742dc550e1469d91812af27101a1"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Internal Research"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "\\x64\\x64passldr.pdb" ascii
    $s2 = "\\amd64\\x64pass.sys" fullword wide
    $s3 = "\\\\.\\DCR" fullword ascii
    $s4 = "Open SC Mgr Error" fullword ascii
    $s5 = "thing is ok " fullword ascii
    $s6 = "x64pass" fullword wide
    $s7 = "%ws\\%ws\\Security" fullword wide
  condition:
    uint16(0) == 0x5a4d and filesize < 200KB and 3 of them
}