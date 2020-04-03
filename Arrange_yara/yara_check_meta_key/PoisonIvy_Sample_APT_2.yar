rule PoisonIvy_Sample_APT_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-03"
    description = "Detects a PoisonIvy Malware"
    family = "None"
    hacker = "None"
    hash = "333f956bf3d5fc9b32183e8939d135bc0fcc5770"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "VT Analysis"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "pidll.dll" fullword ascii /* score: '11.02' */
    $s1 = "sens32.dll" fullword wide /* score: '11.015' */
    $s2 = "9.0.1.56" fullword wide /* score: '9.5' */
    $s3 = "FileDescription" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 19311 times */
    $s4 = "OriginalFilename" fullword wide /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 19040 times */
    $s5 = "ZwSetInformationProcess" fullword ascii /* PEStudio Blacklist: strings */ /* score: '5' */ /* Goodware String - occured 31 times */
    $s6 = "\"%=%14=" fullword ascii /* score: '4.5' */
    $s7 = "091A1G1R1_1g1u1z1" fullword ascii /* score: '4' */ /* Goodware String - occured 1 times */
    $s8 = "gHsMZz" fullword ascii /* score: '3.005' */
    $s9 = "Microsoft Media Device Service Provider" fullword wide /* score: '-3' */ /* Goodware String - occured 8 times */
    $s10 = "Copyright (C) Microsoft Corp." fullword wide /* score: '-7' */ /* Goodware String - occured 12 times */
    $s11 = "MFC42.DLL" fullword ascii /* score: '-31' */ /* Goodware String - occured 36 times */
    $s12 = "MSVCRT.dll" fullword ascii /* score: '-235' */ /* Goodware String - occured 240 times */
    $s13 = "SpecialBuild" fullword wide /* score: '-1561' */ /* Goodware String - occured 1566 times */
    $s14 = "PrivateBuild" fullword wide /* score: '-1585' */ /* Goodware String - occured 1590 times */
    $s15 = "Comments" fullword wide /* score: '-2149' */ /* Goodware String - occured 2154 times */
    $s16 = "040904b0" fullword wide /* score: '-2365' */ /* Goodware String - occured 2370 times */
    $s17 = "LegalTrademarks" fullword wide /* score: '-3518' */ /* Goodware String - occured 3523 times */
    $s18 = "CreateThread" fullword ascii /* score: '-3909' */ /* Goodware String - occured 3914 times */
    $s19 = "ntdll.dll" fullword ascii /* score: '-4675' */ /* Goodware String - occured 4680 times */
    $s20 = "_adjust_fdiv" fullword ascii /* score: '-5450' */ /* Goodware String - occured 5455 times */
  condition:
    uint16(0) == 0x5a4d and filesize < 47KB and all of them
}