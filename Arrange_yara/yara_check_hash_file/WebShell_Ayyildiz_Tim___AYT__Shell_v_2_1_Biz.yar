rule WebShell_Ayyildiz_Tim___AYT__Shell_v_2_1_Biz {
  meta:
    author = Spider
    comment = None
    date = None
    description = PHP Webshells Github Archive - file Ayyildiz Tim  -AYT- Shell v 2.1 Biz.php
    family = 
    hacker = None
    hash = 5fe8c1d01dc5bc70372a8a04410faf8fcde3cb68
    judge = unknown
    license = https://creativecommons.org/licenses/by-nc/4.0/
    reference = None
    threatname = WebShell[Ayyildiz]/Tim...AYT..Shell.v.2.1.Biz
    threattype = Ayyildiz
  strings:
    $s7 = "<meta name=\"Copyright\" content=TouCh By iJOo\">" fullword
    $s11 = "directory... Trust me - it works :-) */" fullword
    $s15 = "/* ls looks much better with ' -F', IMHO. */" fullword
    $s16 = "} else if ($command == 'ls') {" fullword
  condition:
    3 of them
}