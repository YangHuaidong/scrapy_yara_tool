rule RAT_SmallNet {
  meta:
    author = "Spider"
    comment = "None"
    date = "01.04.2014"
    description = "Detects SmallNet RAT"
    family = "None"
    filetype = "exe"
    hacker = "None"
    judge = "black"
    maltype = "Remote Access Trojan"
    reference = "http://malwareconfig.com/stats/SmallNet"
    threatname = "None"
    threattype = "None"
  strings:
    $split1 = "!!<3SAFIA<3!!"
    $split2 = "!!ElMattadorDz!!"
    $a1 = "stub_2.Properties"
    $a2 = "stub.exe" wide
    $a3 = "get_CurrentDomain"
  condition:
    ($split1 or $split2) and (all of ($a*))
}