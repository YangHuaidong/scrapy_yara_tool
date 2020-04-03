rule CN_Honker_mssqlpw_scan {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Script from disclosed CN Honker Pentest Toolset - file mssqlpw scan.txt"
    family = "None"
    hacker = "None"
    hash = "e49def9d72bfef09a639ef3f7329083a0b8b151c"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "response.Write(\"I Get it ! Password is <font color=red>\" & str & \"</font><BR>" ascii /* PEStudio Blacklist: strings */
    $s1 = "response.Write \"Done!<br>Process \" & tTime & \" s\"" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 6KB and all of them
}