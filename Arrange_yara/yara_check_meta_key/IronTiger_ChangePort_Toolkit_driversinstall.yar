rule IronTiger_ChangePort_Toolkit_driversinstall {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Iron Tiger Malware - Changeport Toolkit driverinstall"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://goo.gl/T5fSJC"
    threatname = "None"
    threattype = "None"
  strings:
    $str1 = "openmydoor" nocase wide ascii
    $str2 = "Install service error" nocase wide ascii
    $str3 = "start remove service" nocase wide ascii
    $str4 = "NdisVersion" nocase wide ascii
  condition:
    uint16(0) == 0x5a4d and (2 of ($str*))
}