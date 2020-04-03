rule CN_Honker_Webshell_ASP_asp2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file asp2.txt"
    family = "None"
    hacker = "None"
    hash = "b3ac478e72a0457798a3532f6799adeaf4a7fc87"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<%=server.mappath(request.servervariables(\"script_name\"))%>" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "webshell</font> <font color=#00FF00>" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "Userpwd = \"admin\"   'User Password" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 10KB and all of them
}