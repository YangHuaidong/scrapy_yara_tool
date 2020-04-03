rule IronTiger_Ring_Gh0stvariant {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Iron Tiger Malware - Ring Gh0stvariant"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://goo.gl/T5fSJC"
    threatname = "None"
    threattype = "None"
  strings:
    $str1 = "RING RAT Exception" nocase wide ascii
    $str2 = "(can not update server recently)!" nocase wide ascii
    $str4 = "CreaetProcess Error" nocase wide ascii
    $bla1 = "Sucess!" nocase wide ascii
    $bla2 = "user canceled!" nocase wide ascii
  condition:
    uint16(0) == 0x5a4d and ((any of ($str*)) or (all of ($bla*)))
}