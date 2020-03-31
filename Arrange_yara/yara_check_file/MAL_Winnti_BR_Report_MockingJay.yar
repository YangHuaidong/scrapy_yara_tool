rule MAL_Winnti_BR_Report_MockingJay {
  meta:
    author = Spider
    comment = None
    date = 2019-07-24
    description = Detects Winnti samples
    family = Report
    hacker = None
    judge = unknown
    reference = https://github.com/br-data/2019-winnti-analyse
    threatname = MAL[Winnti]/BR.Report.MockingJay
    threattype = Winnti
  strings:
    $load_magic = { C7 44 ?? ?? FF D8 FF E0 }
    $iter = { e9 ea eb ec ed ee ef f0 }
    $jpeg = { ff d8 ff e0 00 00 00 00 00 00 }
  condition:
    uint16(0) == 0x5a4d and
    $jpeg and
    ($load_magic or $iter in (@jpeg[1]..@jpeg[1]+200)) and
    for any i in (1..#jpeg): ( uint8(@jpeg[i] + 11) != 0 )
}