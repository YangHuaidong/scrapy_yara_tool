rule CN_Honker_Webshell_JSP_jsp {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file jsp.html"
    family = "None"
    hacker = "None"
    hash = "c58fed3d3d1e82e5591509b04ed09cb3675dc33a"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<input name=f size=30 value=shell.jsp>" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "<font color=red>www.i0day.com  By:" fullword ascii
  condition:
    filesize < 3KB and all of them
}