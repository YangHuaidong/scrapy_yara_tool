rule Ayyildiz_Tim___AYT__Shell_v_2_1_Biz_html {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Semi-Auto-generated  - file Ayyildiz Tim  -AYT- Shell v 2.1 Biz.html.txt"
    family = "None"
    hacker = "None"
    hash = "8a8c8bb153bd1ee097559041f2e5cf0a"
    judge = "unknown"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Ayyildiz"
    $s1 = "TouCh By iJOo"
    $s2 = "First we check if there has been asked for a working directory"
    $s3 = "http://ayyildiz.org/images/whosonline2.gif"
  condition:
    2 of them
}