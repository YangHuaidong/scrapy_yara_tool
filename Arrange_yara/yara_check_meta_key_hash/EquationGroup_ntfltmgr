rule EquationGroup_ntfltmgr {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-13"
    description = "EquationGroup Malware - file ntfltmgr.sys"
    family = "None"
    hacker = "None"
    hash1 = "f7a886ee10ee6f9c6be48c20f370514be62a3fd2da828b0dff44ff3d485ff5c5"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/tcSoiJ"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "ntfltmgr.sys" fullword wide
    $s2 = "ntfltmgr.pdb" fullword ascii
    $s4 = "Network Filter Manager" fullword wide
    $s5 = "Corporation. All rights reserved." fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}