rule webshell_cmd_asp_5_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2014/01/28"
    description = "Web Shell - file cmd-asp-5.1.asp"
    family = "None"
    hacker = "None"
    hash = "8baa99666bf3734cbdfdd10088e0cd9f"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "None"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s9 = "Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &" fullword
  condition:
    all of them
}