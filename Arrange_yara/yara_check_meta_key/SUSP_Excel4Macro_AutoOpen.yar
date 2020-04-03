rule SUSP_Excel4Macro_AutoOpen {
  meta:
    author = "Spider"
    comment = "None"
    date = "2020-03-26"
    description = "Detects Excel4 macro use with auto open / close"
    family = "None"
    hacker = "None"
    hash = "2fb198f6ad33d0f26fb94a1aa159fef7296e0421da68887b8f2548bbd227e58f"
    judge = "black"
    reference = "None"
    score = 50
    threatname = "None"
    threattype = "None"
  strings:
    $header_docf = { d0 cf 11 e0 }
    $s1 = "Excel" fullword
    $Auto_Open = { 18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a }
    $Auto_Close = { 18 00 17 00 20 00 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a }
    $Auto_Open1 = { 18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 01 3a }
    $Auto_Close1 = { 18 00 17 00 aa 03 00 01 07 00 00 00 00 00 00 00 00 00 00 02 3a }
  condition:
    filesize < 400KB
    and $header_docf at 0
    and $s1
    and any of ($Auto_*)
}