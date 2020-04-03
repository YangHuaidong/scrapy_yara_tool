rule TA17_293A_Query_XML_Code_MAL_DOC_PT_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "None"
    family = "None"
    hacker = "None"
    judge = "black"
    name = "Query_XML_Code_MAL_DOC_PT_2"
    reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
    threatname = "None"
    threattype = "None"
  strings:
    $dir1 = "word/_rels/settings.xml.rels"
    $bytes = { 8c 90 cd 4e eb 30 10 85 d7 }
  condition:
    uint32(0) == 0x04034b50 and $dir1 and $bytes
}