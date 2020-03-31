rule remview_2003_04_22 {
  meta:
    author = Spider
    comment = None
    date = None
    description = Webshells Auto-generated - file remview_2003_04_22.php
    family = 22
    hacker = None
    hash = 17d3e4e39fbca857344a7650f7ea55e3
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = remview[2003]/04.22
    threattype = 2003
  strings:
    $s1 = "\"<b>\".mm(\"Eval PHP code\").\"</b> (\".mm(\"don't type\").\" \\\"&lt;?\\\""
  condition:
    all of them
}