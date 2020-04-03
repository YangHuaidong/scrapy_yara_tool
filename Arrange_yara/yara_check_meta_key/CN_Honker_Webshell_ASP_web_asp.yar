rule CN_Honker_Webshell_ASP_web_asp {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file web.asp.txt"
    family = "None"
    hacker = "None"
    hash = "aebf6530e89af2ad332062c6aae4a8ca91517c76"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "<FORM method=post target=_blank>ShellUrl: <INPUT " fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "\" >[Copy code]</a> 4ngr7&nbsp; &nbsp;</td>" fullword ascii
  condition:
    filesize < 13KB and all of them
}