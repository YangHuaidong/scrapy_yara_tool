rule EquationGroup_pwdump_Implant {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-13"
    description = "EquationGroup Malware - file pwdump_Implant.dll"
    family = "None"
    hacker = "None"
    hash1 = "dfd5768a4825d1c7329c2e262fde27e2b3d9c810653585b058fcf9efa9815964"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/tcSoiJ"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = ".?AVFeFinallyFailure@@" fullword ascii
    $s8 = ".?AVFeFinallySuccess@@" fullword ascii
    $s3 = "\\system32\\win32k.sys" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 100KB and all of them )
}