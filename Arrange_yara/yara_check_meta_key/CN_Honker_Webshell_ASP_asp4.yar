rule CN_Honker_Webshell_ASP_asp4 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file asp4.txt"
    family = "None"
    hacker = "None"
    hash = "4005b83ced1c032dc657283341617c410bc007b8"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s2 = "if ShellPath=\"\" Then ShellPath = \"cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
    $s6 = "Response.Cookies(Cookie_Login) = sPwd" fullword ascii /* PEStudio Blacklist: strings */
    $s8 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 150KB and all of them
}