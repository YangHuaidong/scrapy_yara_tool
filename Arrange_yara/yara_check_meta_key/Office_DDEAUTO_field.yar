rule Office_DDEAUTO_field {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-10-12"
    description = "Detects DDE in MS Office documents"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $a = /<w:fldChar\s+?w:fldCharType="begin"\/>.{1,1000}?\b[Dd][Dd][Ee][Aa][Uu][Tt][Oo]\b.{1,1000}?<w:fldChar\s+?w:fldCharType="end"\/>/
  condition:
    $a
}