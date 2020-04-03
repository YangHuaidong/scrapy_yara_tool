rule CN_Honker_Webshell_Tuoku_script_mssql_2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file mssql.asp"
    family = "None"
    hacker = "None"
    hash = "ad55512afa109b205e4b1b7968a89df0cf781dc9"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "sqlpass=request(\"sqlpass\")" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "set file=fso.createtextfile(server.mappath(request(\"filename\")),8,true)" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "<blockquote> ServerIP:&nbsp;&nbsp;&nbsp;" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 3KB and all of them
}