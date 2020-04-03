rule SUSP_WordDoc_VBA_Macro_Strings {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-02-12"
    description = "Detects suspicious strings in Word Doc that indcate malicious use of VBA macros"
    family = "None"
    hacker = "None"
    hash1 = "525ba2c8d35f6972ac8fcec8081ae35f6fe8119500be20a4113900fe57d6a0de"
    judge = "unknown"
    reference = "Internal Research"
    score = 60
    threatname = "None"
    threattype = "None"
  strings:
    $a1 = "\\Microsoft Shared\\" ascii
    $a2 = "\\VBA\\" ascii
    $a3 = "Microsoft Office Word" fullword ascii
    $a4 = "PROJECTwm" fullword wide
    $s1 = "AppData" fullword ascii
    $s2 = "Document_Open" fullword ascii
    $s3 = "Project1" fullword ascii
    $s4 = "CreateObject" fullword ascii
  condition:
    uint16(0) == 0xcfd0 and filesize < 800KB and all of them
}