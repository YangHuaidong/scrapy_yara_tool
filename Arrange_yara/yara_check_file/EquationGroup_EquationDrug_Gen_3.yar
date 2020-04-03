rule EquationGroup_EquationDrug_Gen_3 {
   meta:
      description = "EquationGroup Malware - file mssld.dll"
      author = "Auto Generated"
      reference = "https://goo.gl/tcSoiJ"
      date = "2017-01-13"
      hash1 = "69dcc150468f7707cc8ef618a4cea4643a817171babfba9290395ada9611c63c"
   strings:
      $op1 = { f4 65 c6 45 f5 6c c6 45 f6 33 c6 45 f7 32 c6 45 }
      $op2 = { 36 c6 45 e6 34 c6 45 e7 50 c6 45 e8 72 c6 45 e9 }
      $op3 = { c6 45 e8 65 c6 45 e9 70 c6 45 ea 74 c6 45 eb 5f }
   condition:
      ( uint16(0) == 0x5a4d and filesize < 1000KB and all of them )
}