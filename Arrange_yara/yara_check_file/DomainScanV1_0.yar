rule DomainScanV1_0 {
  meta:
    author = Spider
    comment = None
    date = None
    description = Auto-generated rule on file DomainScanV1_0.exe
    family = None
    hacker = None
    hash = aefcd73b802e1c2bdc9b2ef206a4f24e
    judge = unknown
    reference = None
    threatname = DomainScanV1[0
    threattype = 0.yar
  strings:
    $s0 = "dIJMuX$aO-EV"
    $s1 = "XELUxP\"-\\"
    $s2 = "KaR\"U'}-M,."
    $s3 = "V.)\\ZDxpLSav"
    $s4 = "Decompress error"
    $s5 = "Can't load library"
    $s6 = "Can't load function"
    $s7 = "com0tl32:.d"
  condition:
    all of them
}