rule IronTiger_PlugX_Server {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Iron Tiger Malware - PlugX Server"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://goo.gl/T5fSJC"
    threatname = "None"
    threattype = "None"
  strings:
    $str1 = "\\UnitFrmManagerKeyLog.pas" nocase wide ascii
    $str2 = "\\UnitFrmManagerRegister.pas" nocase wide ascii
    $str3 = "Input Name..." nocase wide ascii
    $str4 = "New Value#" nocase wide ascii
    $str5 = "TThreadRControl.Execute SEH!!!" nocase wide ascii
    $str6 = "\\UnitFrmRControl.pas" nocase wide ascii
    $str7 = "OnSocket(event is error)!" nocase wide ascii
    $str8 = "Make 3F Version Ok!!!" nocase wide ascii
    $str9 = "PELEASE DO NOT CHANGE THE DOCAMENT" nocase wide ascii
    $str10 = "Press [Ok] Continue Run, Press [Cancel] Exit" nocase wide ascii
  condition:
    uint16(0) == 0x5a4d and (2 of ($str*))
}