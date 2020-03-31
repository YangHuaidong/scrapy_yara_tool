rule RemExp_asp {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - file RemExp.asp.txt
    family = None
    hacker = None
    hash = aa1d8491f4e2894dbdb91eec1abc2244
    judge = unknown
    reference = None
    threatname = RemExp[asp
    threattype = asp.yar
  strings:
    $s0 = "<title>Remote Explorer</title>"
    $s3 = " FSO.CopyFile Request.QueryString(\"FolderPath\") & Request.QueryString(\"CopyFi"
    $s4 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f"
  condition:
    2 of them
}