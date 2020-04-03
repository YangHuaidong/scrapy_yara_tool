rule Sofacy_Bundestag_Batch {
    meta:
        description = "Sofacy Bundestags APT Batch Script"
        license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
        reference = "http://dokumente.linksfraktion.de/inhalt/report-orig.pdf"
        date = "2015-06-19"
        score = 70
    strings:
        $s1 = "for %%G in (.pdf, .xls, .xlsx, .doc, .docx)" ascii
        $s2 = "cmd /c copy"
        $s3 = "forfiles"
    condition:
        filesize < 10KB and 2 of them
}