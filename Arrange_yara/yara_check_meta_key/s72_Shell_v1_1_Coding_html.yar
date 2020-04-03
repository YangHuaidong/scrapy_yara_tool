rule s72_Shell_v1_1_Coding_html {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file s72 Shell v1.1 Coding.html.txt"
    family = "None"
    hacker = "None"
    hash = "c2e8346a5515c81797af36e7e4a3828e"
    judge = "black"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Dizin</font></b></font><font face=\"Verdana\" style=\"font-size: 8pt\"><"
    $s1 = "s72 Shell v1.0 Codinf by Cr@zy_King"
    $s3 = "echo \"<p align=center>Dosya Zaten Bulunuyor</p>\""
  condition:
    1 of them
}