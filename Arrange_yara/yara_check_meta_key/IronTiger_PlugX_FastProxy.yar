rule IronTiger_PlugX_FastProxy {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Iron Tiger Malware - PlugX FastProxy"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://goo.gl/T5fSJC"
    threatname = "None"
    threattype = "None"
  strings:
    $str1 = "SAFEPROXY HTServerTimer Quit!" nocase wide ascii
    $str2 = "Useage: %s pid" nocase wide ascii
    $str3 = "%s PORT[%d] TO PORT[%d] SUCCESS!" nocase wide ascii
    $str4 = "p0: port for listener" nocase wide ascii
    $str5 = "\\users\\whg\\desktop\\plug\\" nocase wide ascii
    $str6 = "[+Y] cwnd : %3d, fligth:" nocase wide ascii
  condition:
    uint16(0) == 0x5a4d and (any of ($str*))
}