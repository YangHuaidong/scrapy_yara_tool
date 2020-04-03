rule APT_HiddenCobra_enc_PK_header {
  meta:
    author = "Spider"
    category = "hidden_cobra"
    comment = "None"
    date = "2018-04-12"
    description = "Hidden Cobra - Detects trojan with encrypted header"
    family = "TYPEFRAME"
    hacker = "None"
    hash0 = "3229a6cea658b1b3ca5ca9ad7b40d8d4"
    incident = "10135536"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/analysis-reports/AR18-165A"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = { 5f a8 80 c5 a0 87 c7 f0 9e e6 }
    $s1 = { 95 f1 6e 9c 3f c1 2c 88 a0 5a }
    $s2 = { ae 1d af 74 c0 f5 e1 02 50 10 }
  condition:
    (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and any of them
}