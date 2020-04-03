rule Office_OLE_DDE {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-10-12"
    description = "Detects DDE in MS Office documents"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $a = /\x13\s*DDE\b[^\x14]+/ nocase
    $r1 = { 52 00 6f 00 6f 00 74 00 20 00 45 00 6e 00 74 00 72 00 79 }
    $r2 = "Adobe ARM Installer"
  condition:
    uint32be(0) == 0xD0CF11E0 and $a and not 1 of ($r*)
}