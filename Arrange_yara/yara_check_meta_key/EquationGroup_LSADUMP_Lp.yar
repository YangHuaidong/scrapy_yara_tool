rule EquationGroup_LSADUMP_Lp {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-13"
    description = "EquationGroup Malware - file LSADUMP_Lp.dll"
    family = "None"
    hacker = "None"
    hash1 = "c7bf4c012293e7de56d86f4f5b4eeb6c1c5263568cc4d9863a286a86b5daf194"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/tcSoiJ"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "LSADUMP - - ERROR - - Injected" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 300KB and 1 of them )
}