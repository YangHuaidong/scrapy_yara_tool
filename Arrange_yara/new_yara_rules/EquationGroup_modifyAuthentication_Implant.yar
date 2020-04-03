rule EquationGroup_modifyAuthentication_Implant {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-13"
    description = "EquationGroup Malware - file modifyAuthentication_Implant.dll"
    family = "None"
    hacker = "None"
    hash1 = "e1dff24af5bfc991dca21b4e3a19ffbc069176d674179eef691afc6b1ac6f805"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/tcSoiJ"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "LSASS.EXE" fullword wide
    $s2 = "hsamsrv.dll" fullword ascii
    $s3 = "hZwOpenProcess" fullword ascii
    $s4 = "hOpenProcess" fullword ascii
    $s5 = ".?AVFeFinallyFailure@@" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}