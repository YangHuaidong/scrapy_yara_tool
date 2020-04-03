rule CN_Honker_Webshell_ASP_hy2006a {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file hy2006a.txt"
    family = "None"
    hacker = "None"
    hash = "20da92b2075e6d96636f883dcdd3db4a38c01090"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s15 = "Const myCmdDotExeFile = \"command.com\"" fullword ascii /* PEStudio Blacklist: strings */
    $s16 = "If LCase(appName) = \"cmd.exe\" And appArgs <> \"\" Then" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 406KB and all of them
}