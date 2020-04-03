rule CN_Honker_Webshell_nc_1 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file 1.txt"
    family = "None"
    hacker = "None"
    hash = "51d83961171db000fe4476f36d703ef3de409676"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; Mozilla/4.0 " ascii /* PEStudio Blacklist: agent */
    $s2 = "<%if session(\"pw\")<>\"go\" then %>" fullword ascii
  condition:
    filesize < 11KB and all of them
}