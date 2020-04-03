rule SuperScan4 {
  meta:
    author = "Spider"
    comment = "None"
    date = "None"
    description = "Auto-generated rule on file SuperScan4.exe"
    family = "None"
    hacker = "None"
    hash = "78f76428ede30e555044b83c47bc86f0"
    judge = "unknown"
    reference = "None"
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = " td class=\"summO1\">"
    $s6 = "REM'EBAqRISE"
    $s7 = "CorExitProcess'msc#e"
  condition:
    all of them
}