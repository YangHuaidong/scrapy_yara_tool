rule APT_NK_AR18_165A_HiddenCobra_import_deob {
  meta:
    author = "Spider"
    category = "hidden_cobra"
    comment = "None"
    date = "2018-04-12"
    description = "Hidden Cobra - Detects installed proxy module as a service"
    family = "TYPEFRAME"
    hacker = "None"
    incident = "10135536"
    judge = "black"
    md5 = "ae769e62fef4a1709c12c9046301aa5d"
    md5 = "e48fe20eblf5a5887f2ac631fed9ed63"
    reference = "https://www.us-cert.gov/ncas/analysis-reports/AR18-165A"
    threatname = "None"
    threattype = "None"
  strings:
    $ = { 8a 01 3c 62 7c 0a 3c 79 7f 06 b2 db 2a d0 88 11 8a 41 01 41 84 c0 75 e8 }
    $ = { 8a 08 80 f9 62 7c 0b 80 f9 79 7f 06 82 db 2a d1 88 10 8a 48 01 40 84 c9 75 e6 }
  condition:
    (uint16(0) == 0x5A4D and uint16(uint32(0x3c)) == 0x4550) and any of them
}