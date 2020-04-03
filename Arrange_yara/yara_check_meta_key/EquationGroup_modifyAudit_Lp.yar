rule EquationGroup_modifyAudit_Lp {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-13"
    description = "EquationGroup Malware - file modifyAudit_Lp.dll"
    family = "None"
    hacker = "None"
    hash1 = "2a1f2034e80421359e3bf65cbd12a55a95bd00f2eb86cf2c2d287711ee1d56ad"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/tcSoiJ"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Read of audit related process memory failed" fullword wide
    $s2 = "** This may indicate that another copy of modify_audit is already running **" fullword wide
    $s3 = "Pattern match of code failed" fullword wide
    $s4 = "Base for necessary auditing dll not found" fullword wide
    $s5 = "Security auditing has been disabled" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 300KB and 3 of them ) or ( all of them )
}