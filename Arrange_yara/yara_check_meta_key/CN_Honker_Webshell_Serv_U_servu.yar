rule CN_Honker_Webshell_Serv_U_servu {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file servu.php"
    family = "None"
    hacker = "None"
    hash = "7de701b86820096e486e64ca34f1fa9f2fbba641"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "fputs ($conn_id, \"SITE EXEC \".$dir.\"cmd.exe /c \".$cmd.\"\\r\\n\");" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "function ftpcmd($ftpport,$user,$password,$dir,$cmd){" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 41KB and all of them
}