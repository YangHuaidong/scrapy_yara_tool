rule PoisonIvy_RAT_ssMUIDLL {
  meta:
    author = "Spider"
    comment = "None"
    date = "2016-04-22"
    description = "Detects PoisonIvy RAT DLL mentioned in Palo Alto Blog in April 2016"
    family = "None"
    hacker = "None"
    hash1 = "7a424ad3f3106b87e8e82c7125834d7d8af8730a2a97485a639928f66d5f6bf4"
    hash2 = "6eb7657603edb2b75ed01c004d88087abe24df9527b272605b8517a423557fe6"
    hash3 = "2a6ef9dde178c4afe32fe676ff864162f104d85fac2439986de32366625dc083"
    hash4 = "8b805f508879ecdc9bba711cfbdd570740c4825b969c1b4db980c134ac8fef1c"
    hash5 = "ac99d4197e41802ff9f8852577955950332947534d8e2a0e3b6c1dd1715490d4"
    judge = "unknown"
    reference = "http://goo.gl/WiwtYT"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "ssMUIDLL.dll" fullword ascii
    $op1 = { 6a 00 c6 07 e9 ff d6 } // sample=e9ccf4e139bbbd114b67cc3cee260d1cb638c9d0 address=0x10001f81
    $op2 = { 02 cb 6a 00 88 0f ff d6 47 ff 4d fc 75 } // sample=e9ccf4e139bbbd114b67cc3cee260d1cb638c9d0 address=0x100012a9
    $op3 = { 6a 00 88 7f 02 ff d6 } // sample=e9ccf4e139bbbd114b67cc3cee260d1cb638c9d0 address=0x10001f93
  condition:
    ( uint16(0) == 0x5a4d and filesize < 20KB and ( all of ($op*) ) ) or ( all of them )
}