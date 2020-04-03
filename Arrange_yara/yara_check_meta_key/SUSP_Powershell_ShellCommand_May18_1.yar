rule SUSP_Powershell_ShellCommand_May18_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2018-05-18"
    description = "Detects a supcicious powershell commandline"
    family = "None"
    hacker = "None"
    hash1 = "8328806700696ffe8cc37a0b81a67a6e9c86bb416364805b8aceaee5db17333f"
    judge = "black"
    reference = "https://github.com/0x00-0x00/ShellPop"
    threatname = "None"
    threattype = "None"
  strings:
    $x1 = "powershell -nop -ep bypass -Command" ascii
  condition:
    filesize < 3KB and 1 of them
}