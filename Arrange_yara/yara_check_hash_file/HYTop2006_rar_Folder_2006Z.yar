rule HYTop2006_rar_Folder_2006Z {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file 2006Z.exe
    family = 2006Z
    hacker = None
    hash = fd1b6129abd4ab177fed135e3b665488
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = HYTop2006[rar]/Folder.2006Z
    threattype = rar
  strings:
    $s1 = "wangyong,czy,allen,lcx,Marcos,kEvin1986,myth"
    $s8 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x"
  condition:
    all of them
}