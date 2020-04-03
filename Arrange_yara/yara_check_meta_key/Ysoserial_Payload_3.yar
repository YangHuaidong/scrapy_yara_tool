rule Ysoserial_Payload_3 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-02-04"
    description = "Ysoserial Payloads - from files JavassistWeld1.bin, JBossInterceptors.bin"
    family = "None"
    hacker = "None"
    hash1 = "f0d2f1095da0164c03a0e801bd50f2f06793fb77938e53b14b57fd690d036929"
    hash2 = "5466d47363e11cd1852807b57d26a828728b9d5a0389214181b966bd0d8d7e56"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "https://github.com/frohoff/ysoserial"
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "ysoserialq" fullword ascii
    $s1 = "targetClassInterceptorMetadatat" fullword ascii
    $s2 = "targetInstancet" fullword ascii
    $s3 = "targetClassL" fullword ascii
    $s4 = "POST_ACTIVATEsr" fullword ascii
    $s5 = "PRE_DESTROYsq" fullword ascii
  condition:
    ( uint16(0) == 0xedac and filesize < 10KB and $x1 ) or ( all of them )
}