rule HYTop2006_rar_Folder_2006Z {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Webshells Auto-generated - file 2006Z.exe"
    family = "None"
    hacker = "None"
    hash = "fd1b6129abd4ab177fed135e3b665488"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "wangyong,czy,allen,lcx,Marcos,kEvin1986,myth"
    $s8 = "System\\CurrentControlSet\\Control\\Keyboard Layouts\\%.8x"
  condition:
    all of them
}