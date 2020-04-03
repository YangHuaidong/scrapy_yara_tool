rule HKTL_Keyword_InjectDLL {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-04-04"
    description = "Detects suspicious InjectDLL keyword found in hacktools or possibly unwanted applications"
    family = "None"
    hacker = "None"
    hash1 = "2e7b4141e1872857904a0ef2d87535fd913cbdd9f964421f521b5a228a492a29"
    judge = "black"
    reference = "https://github.com/zerosum0x0/koadic"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "InjectDLL" fullword ascii
    $s4 = "Kernel32.dll" fullword ascii
  condition:
    uint16(0) == 0x5a4d and all of them
}