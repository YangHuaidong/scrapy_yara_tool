rule HKTL_EmbeddedPDF {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-07-25"
    description = "Detects Embedded PDFs which can start malicious content"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://twitter.com/infosecn1nja/status/1021399595899731968?s=12"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "/Type /Action\n /S /JavaScript\n /JS (this.exportDataObject({" fullword ascii
    $s1 = "(This PDF document embeds file" fullword ascii
    $s2 = "/Names << /EmbeddedFiles << /Names" fullword ascii
    $s3 = "/Type /EmbeddedFile" fullword ascii
  condition:
    uint16(0) == 0x5025 and
    2 of ($s*) and $x1
}