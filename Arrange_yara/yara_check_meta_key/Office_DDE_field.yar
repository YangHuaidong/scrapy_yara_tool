rule Office_DDE_field {
  meta:
    author = "Spider"
    comment = "None"
    date = "2017-10-12"
    description = "Detects DDE in MS Office documents"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
    score = 40
    threatname = "None"
    threattype = "None"
  strings:
    $a = /<w:fldChar\s+?w:fldCharType="begin"\/>.+?\b[Dd][Dd][Ee]\b.+?<w:fldChar\s+?w:fldCharType="end"\/>/
  condition:
    $a
}