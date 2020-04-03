rule EquationGroup_Toolset_Apr17__NameProbe_SMBTOUCH_14 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-04-15"
    description = "Detects EquationGroup Tool - April Leak"
    family = "None"
    hacker = "None"
    hash1 = "fbe3a4501654438f502a93f51b298ff3abf4e4cad34ce4ec0fad5cb5c2071597"
    hash2 = "7da350c964ea43c149a12ac3d2ce4675cedc079ddc10d1f7c464b16688305309"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://steemit.com/shadowbrokers/@theshadowbrokers/lost-in-translation"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "DEC Pathworks TCPIP service on Windows NT" fullword ascii
    $s2 = "<\\\\__MSBROWSE__> G" fullword ascii
    $s3 = "<IRISNAMESERVER>" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}