rule SUSP_XORed_MSDOS_Stub_Message {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-10-28"
    description = "Detects suspicious XORed MSDOS stub message"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://yara.readthedocs.io/en/latest/writingrules.html#xor-strings"
    score = 55
    threatname = "None"
    threattype = "None"
  strings:
    $xo1 = "This program cannot be run in DOS mode" xor ascii wide
    $xo2 = "This program must be run under Win32" xor ascii wide
    $xof1 = "This program cannot be run in DOS mode" ascii wide
    $xof2 = "This program must be run under Win32" xor ascii wide
  condition:
    1 of ($xo*) and not 1 of ($xof*)
}