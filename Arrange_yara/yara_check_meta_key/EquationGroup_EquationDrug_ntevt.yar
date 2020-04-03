rule EquationGroup_EquationDrug_ntevt {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-13"
    description = "EquationGroup Malware - file ntevt.sys"
    family = "None"
    hacker = "None"
    hash1 = "45e5e1ea3456d7852f5c610c7f4447776b9f15b56df7e3a53d57996123e0cebf"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/tcSoiJ"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "ntevt.sys" fullword ascii
    $s2 = "c:\\ntevt.pdb" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 500KB and all of them )
}