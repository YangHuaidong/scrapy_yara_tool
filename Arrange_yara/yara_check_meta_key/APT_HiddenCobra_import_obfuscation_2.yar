rule APT_HiddenCobra_import_obfuscation_2 {
  meta:
    author = "Spider"
    category = "hidden_cobra"
    comment = "None"
    date = "2018-04-12"
    description = "Hidden Cobra - Detects remote access trojan"
    family = "TYPEFRAME"
    hacker = "None"
    hash0 = "bfb41bc0c3856aa0a81a5256b7b8da51"
    incident = "10135536"
    judge = "black"
    reference = "https://www.us-cert.gov/ncas/analysis-reports/AR18-165A"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = { a6 d6 02 eb 4e b2 41 eb c3 ef 1f }
    $s1 = { b6 df 01 fd 48 b5 }
    $s2 = { b6 d5 0e f3 4e b5 }
    $s3 = { b7 df 0e ee }
    $s4 = { b6 df 03 fc }
    $s5 = { a7 d3 03 fc }
  condition:
    (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and all of them
}