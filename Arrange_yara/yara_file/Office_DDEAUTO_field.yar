rule Office_DDEAUTO_field {
   meta:
      description = "Detects DDE in MS Office documents"
      author = "NVISO Labs"
      reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
      date = "2017-10-12"
      score = 60
   strings:
      $a = /<w:fldChar\s+?w:fldCharType="begin"\/>.{1,1000}?\b[Dd][Dd][Ee][Aa][Uu][Tt][Oo]\b.{1,1000}?<w:fldChar\s+?w:fldCharType="end"\/>/
   condition:
      $a
}