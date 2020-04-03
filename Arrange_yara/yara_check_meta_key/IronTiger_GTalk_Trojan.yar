rule IronTiger_GTalk_Trojan {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Iron Tiger Malware - GTalk Trojan"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://goo.gl/T5fSJC"
    threatname = "None"
    threattype = "None"
  strings:
    $str1 = "gtalklite.com" nocase wide ascii
    $str2 = "computer=%s&lanip=%s&uid=%s&os=%s&data=%s" nocase wide ascii
    $str3 = "D13idmAdm" nocase wide ascii
    $str4 = "Error: PeekNamedPipe failed with %i" nocase wide ascii
  condition:
    uint16(0) == 0x5a4d and (2 of ($str*))
}