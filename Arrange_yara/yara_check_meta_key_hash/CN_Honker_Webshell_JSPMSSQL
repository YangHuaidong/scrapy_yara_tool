rule CN_Honker_Webshell_JSPMSSQL {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file JSPMSSQL.txt"
    family = "None"
    hacker = "None"
    hash = "c6b4faecd743d151fe0a4634e37c9a5f6533655f"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<form action=\"?action=operator&cmd=execute\"" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "String sql = request.getParameter(\"sqlcmd\");" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 35KB and all of them
}