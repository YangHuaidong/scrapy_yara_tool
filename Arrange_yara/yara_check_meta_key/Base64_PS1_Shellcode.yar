rule Base64_PS1_Shellcode {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-11-14"
    description = "Detects Base64 encoded PS1 Shellcode"
    family = "None"
    hacker = "None"
    judge = "black"
    reference = "https://twitter.com/ItsReallyNick/status/1062601684566843392"
    score = 65
    threatname = "None"
    threattype = "None"
  strings:
    $substring = "AAAAYInlM"
    $pattern1 = "/OiCAAAAYInlM"
    $pattern2 = "/OiJAAAAYInlM"
  condition:
    $substring and 1 of ($p*)
}