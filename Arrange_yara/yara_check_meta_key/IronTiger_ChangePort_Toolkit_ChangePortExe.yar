rule IronTiger_ChangePort_Toolkit_ChangePortExe {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Iron Tiger Malware - Toolkit ChangePort"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://goo.gl/T5fSJC"
    threatname = "None"
    threattype = "None"
  strings:
    $str1 = "Unable to alloc the adapter!" nocase wide ascii
    $str2 = "Wait for master fuck" nocase wide ascii
    $str3 = "xx.exe <HOST> <PORT>" nocase wide ascii
    $str4 = "chkroot2007" nocase wide ascii
    $str5 = "Door is bind on %s" nocase wide ascii
  condition:
    uint16(0) == 0x5a4d and (2 of ($str*))
}