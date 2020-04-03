rule EquationGroup_EquationDrug_Gen_4 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-01-13"
    description = "EquationGroup Malware - file PC_Level4_flav_dll"
    family = "None"
    hacker = "None"
    hash1 = "227faeb770ba538fb85692b3dfcd00f76a0a5205d1594bd0969a1e535ee90ee1"
    judge = "unknown"
    reference = "https://goo.gl/tcSoiJ"
    threatname = "None"
    threattype = "None"
  strings:
    $op1 = { 11 8b da 23 df 8d 1c 9e c1 fb 02 33 da 23 df 33 }
    $op2 = { c3 0c 57 8b 3b eb 27 8b f7 83 7e 08 00 8b 3f 74 }
    $op3 = { 00 0f b7 5e 14 8d 5c 33 18 8b c3 2b 45 08 50 ff }
  condition:
    ( uint16(0) == 0x5a4d and filesize < 300KB and all of them )
}