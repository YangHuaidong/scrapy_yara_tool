rule EquationGroup_PC_Level4_flav_dll_x64 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-13"
    description = "EquationGroup Malware - file PC_Level4_flav_dll_x64"
    family = "None"
    hacker = "None"
    hash1 = "25a2549031cb97b8a3b569b1263c903c6c0247f7fff866e7ec63f0add1b4921c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://goo.gl/tcSoiJ"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "wship.dll" fullword wide
    $s2 = "   IP:      " fullword ascii
    $s3 = "\\\\.\\%hs" fullword ascii
  condition:
    ( uint16(0) == 0x5a4d and filesize < 200KB and all of them )
}