rule SUSP_Base64_Encoded_Hex_Encoded_Code {
  meta:
    author = "Spider"
    comment = "None"
    date = "2019-04-29"
    description = "Detects hex encoded code that has been base64 encoded"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://www.nextron-systems.com/2019/04/29/spotlight-threat-hunting-yara-rule-example/"
    score = 65
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = { 78 34 4e ?? ?? 63 65 44 ?? ?? 58 48 67 }
    $x2 = { 63 45 44 ?? ?? 58 48 67 ?? ?? ?? 78 34 4e }
    $fp1 = "Microsoft Azure Code Signp$"
  condition:
    1 of ($x*) and not 1 of ($fp*)
}