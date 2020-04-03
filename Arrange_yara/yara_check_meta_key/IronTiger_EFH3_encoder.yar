rule IronTiger_EFH3_encoder {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Iron Tiger EFH3 Encoder"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "http://goo.gl/T5fSJC"
    threatname = "None"
    threattype = "None"
  strings:
    $str1 = "EFH3 [HEX] [SRCFILE] [DSTFILE]" nocase wide ascii
    $str2 = "123.EXE 123.EFH" nocase wide ascii
    $str3 = "ENCODER: b[i]: = " nocase wide ascii
  condition:
    uint16(0) == 0x5a4d and (any of ($str*))
}