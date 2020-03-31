rule cmd_asp_5_1_asp {
  meta:
    author = Spider
    comment = None
    date = None
    description = Semi-Auto-generated  - file cmd-asp-5.1.asp.txt
    family = 1
    hacker = None
    hash = 8baa99666bf3734cbdfdd10088e0cd9f
    judge = unknown
    reference = None
    threatname = cmd[asp]/5.1.asp
    threattype = asp
  strings:
    $s0 = "Call oS.Run(\"win.com cmd.exe /c del \"& szTF,0,True)" fullword
    $s3 = "Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &" fullword
  condition:
    1 of them
}