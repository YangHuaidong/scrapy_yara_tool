rule SUSP_OfficeDoc_VBA_Base64Decode {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-06-21"
    description = "Detects suspicious VBA code with Base64 decode functions"
    family = "None"
    hacker = "None"
    hash1 = "52262bb315fa55b7441a04966e176b0e26b7071376797e35c80aa60696b6d6fc"
    judge = "black"
    reference = "https://github.com/cpaton/Scripting/blob/master/VBA/Base64.bas"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "B64_CHAR_DICT" ascii
    $s2 = "Base64Decode" ascii
    $s3 = "Base64Encode" ascii
  condition:
    uint16(0) == 0xcfd0 and filesize < 60KB and 2 of them
}