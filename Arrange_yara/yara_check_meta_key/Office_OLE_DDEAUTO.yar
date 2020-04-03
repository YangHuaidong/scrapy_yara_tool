rule Office_OLE_DDEAUTO {
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
    $a = /\x13\s*DDEAUTO\b[^\x14]+/ nocase
  condition:
    uint32be(0) == 0xD0CF11E0 and $a
}