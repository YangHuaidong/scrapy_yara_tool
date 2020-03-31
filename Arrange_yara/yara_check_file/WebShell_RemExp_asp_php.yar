rule WebShell_RemExp_asp_php {
  meta:
    author = Spider
    comment = None
    date = None
    description = PHP Webshells Github Archive - file RemExp.asp.php.txt
    family = php
    hacker = None
    hash = d9919dcf94a70d5180650de8b81669fa1c10c5a2
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = WebShell[RemExp]/asp.php
    threattype = RemExp
  strings:
    $s0 = "lsExt = Right(FileName, Len(FileName) - liCount)" fullword
    $s7 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f"
    $s13 = "Response.Write Drive.ShareName & \" [share]\"" fullword
    $s19 = "If Request.QueryString(\"CopyFile\") <> \"\" Then" fullword
    $s20 = "<td width=\"40%\" height=\"20\" bgcolor=\"silver\">  Name</td>" fullword
  condition:
    all of them
}