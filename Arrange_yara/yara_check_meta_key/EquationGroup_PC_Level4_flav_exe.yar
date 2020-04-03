rule EquationGroup_PC_Level4_flav_exe {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-13"
    description = "EquationGroup Malware - file PC_Level4_flav_exe"
    family = "None"
    hacker = "None"
    hash1 = "33ba9f103186b6e52d8d69499512e7fbac9096e7c5278838127488acc3b669a9"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/tcSoiJ"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "Extended Memory Runtime Process" fullword wide
    $s2 = "memess.exe" fullword wide
    $s3 = "\\\\.\\%hs" fullword ascii
    $s4 = ".?AVOpenSocket@@" fullword ascii
    $s5 = "Corporation. All rights reserved." fullword wide
    $s6 = "itanium" fullword wide
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}