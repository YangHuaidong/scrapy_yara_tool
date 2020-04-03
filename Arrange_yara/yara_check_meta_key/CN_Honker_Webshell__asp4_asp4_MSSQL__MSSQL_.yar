rule CN_Honker_Webshell__asp4_asp4_MSSQL__MSSQL_ {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - from files asp4.txt, asp4.txt, MSSQL_.asp, MSSQL_.asp"
    family = "None"
    hacker = "None"
    hash0 = "4005b83ced1c032dc657283341617c410bc007b8"
    hash1 = "4005b83ced1c032dc657283341617c410bc007b8"
    hash2 = "7097c21f92306983add3b5b29a517204cd6cd819"
    hash3 = "7097c21f92306983add3b5b29a517204cd6cd819"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    super_rule = 1
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "\"<form name=\"\"searchfileform\"\" action=\"\"?action=searchfile\"\" method=\"" ascii /* PEStudio Blacklist: strings */
    $s1 = "\"<TD ALIGN=\"\"Left\"\" colspan=\"\"5\"\">[\"& DbName & \"]" fullword ascii
    $s2 = "Set Conn = Nothing " fullword ascii
  condition:
    filesize < 341KB and all of them
}