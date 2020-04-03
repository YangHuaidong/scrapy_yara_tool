rule CN_Honker_Webshell_ASP_asp1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file asp1.txt"
    family = "None"
    hacker = "None"
    hash = "78b5889b363043ed8a60bed939744b4b19503552"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "SItEuRl=" ascii
    $s2 = "<%@ LANGUAGE = VBScript.Encode %><%" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "Server.ScriptTimeout=" ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 200KB and all of them
}