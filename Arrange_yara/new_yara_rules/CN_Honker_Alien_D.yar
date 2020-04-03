rule CN_Honker_Alien_D {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Script from disclosed CN Honker Pentest Toolset - file D.ASP"
    family = "None"
    hacker = "None"
    hash = "de9cd4bd72b1384b182d58621f51815a77a5f07d"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "Paths_str=\"c:\\windows\\\"&chr(13)&chr(10)&\"c:\\Documents and Settings\\\"&chr" ascii /* PEStudio Blacklist: strings */
    $s1 = "CONST_FSO=\"Script\"&\"ing.Fil\"&\"eSyst\"&\"emObject\"" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "Response.Write \"<form id='form1' name='form1' method='post' action=''>\"" fullword ascii /* PEStudio Blacklist: strings */
    $s3 = "set getAtt=FSO.GetFile(filepath)" fullword ascii
    $s4 = "Response.Write \"<input name='NoCheckTemp' type='checkbox' id='NoCheckTemp' chec" ascii
  condition:
    filesize < 30KB and 2 of them
}