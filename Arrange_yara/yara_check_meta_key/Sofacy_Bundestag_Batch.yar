rule Sofacy_Bundestag_Batch {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-19"
    description = "Sofacy Bundestags APT Batch Script"
    family = "None"
    hacker = "None"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "for %%G in (.pdf, .xls, .xlsx, .doc, .docx)" ascii
    $s2 = "cmd /c copy"
    $s3 = "forfiles"
  condition:
    filesize < 10KB and 2 of them
}