rule ZXshell2_0_rar_Folder_ZXshell {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file ZXshell.exe
    family = Folder
    hacker = None
    hash = 246ce44502d2f6002d720d350e26c288
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = ZXshell2[0]/rar.Folder.ZXshell
    threattype = 0
  strings:
    $s0 = "WPreviewPagesn"
    $s1 = "DA!OLUTELY N"
  condition:
    all of them
}