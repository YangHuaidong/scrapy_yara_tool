rule HYTop2006_rar_Folder_2006 {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file 2006.asp
    family = 2006
    hacker = None
    hash = c19d6f4e069188f19b08fa94d44bc283
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = HYTop2006[rar]/Folder.2006
    threattype = rar
  strings:
    $s6 = "strBackDoor = strBackDoor "
  condition:
    all of them
}