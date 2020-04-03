rule SUSP_Obfuscted_PowerShell_Code {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-12-13"
    description = "Detects obfuscated PowerShell Code"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://twitter.com/silv0123/status/1073072691584880640"
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "').Invoke(" ascii
    $s2 = "(\"{1}{0}\"" ascii
    $s3 = "{0}\" -f" ascii
  condition:
    #s1 > 11 and #s2 > 10 and #s3 > 10
}