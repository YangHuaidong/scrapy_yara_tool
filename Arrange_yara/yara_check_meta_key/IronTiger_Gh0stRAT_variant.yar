rule IronTiger_Gh0stRAT_variant {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "This is a detection for a s.exe variant seen in Op. Iron Tiger"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://goo.gl/T5fSJC"
    threatname = "None"
    threattype = "None"
  strings:
    $str1 = "Game Over Good Luck By Wind" nocase wide ascii
    $str2 = "ReleiceName" nocase wide ascii
    $str3 = "jingtisanmenxiachuanxiao.vbs" nocase wide ascii
    $str4 = "Winds Update" nocase wide ascii fullword
  condition:
    uint16(0) == 0x5a4d and (any of ($str*))
    and not filename == "UpdateSystemMib.exe"
}