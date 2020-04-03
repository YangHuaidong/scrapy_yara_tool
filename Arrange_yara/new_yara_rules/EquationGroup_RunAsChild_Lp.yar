rule EquationGroup_RunAsChild_Lp {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-13"
    description = "EquationGroup Malware - file RunAsChild_Lp.dll"
    family = "None"
    hacker = "None"
    hash1 = "1097e1d562341858e241f1f67788534c0e340a2dc2e75237d57e3f473e024464"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/tcSoiJ"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Privilege elevation failed" fullword wide
    $s2 = "Unable to open parent process" fullword wide
    $s4 = "Invalid input to lpRunAsChildPPC" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}