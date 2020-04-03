rule IronTiger_ReadPWD86 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Iron Tiger Malware - ReadPWD86"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://goo.gl/T5fSJC"
    threatname = "None"
    threattype = "None"
  strings:
    $str1 = "Fail To Load LSASRV" nocase wide ascii
    $str2 = "Fail To Search LSASS Data" nocase wide ascii
    $str3 = "User Principal" nocase wide ascii
  condition:
    uint16(0) == 0x5a4d and (all of ($str*))
}