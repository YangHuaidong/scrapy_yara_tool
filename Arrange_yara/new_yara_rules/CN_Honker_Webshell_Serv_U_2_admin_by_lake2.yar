rule CN_Honker_Webshell_Serv_U_2_admin_by_lake2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file Serv-U 2 admin by lake2.asp"
    family = "None"
    hacker = "None"
    hash = "cb8039f213e611ab2687edd23e63956c55f30578"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "xPost3.Open \"POST\", \"http://127.0.0.1:\"& port &\"/lake2\", True" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "response.write \"FTP user lake  pass admin123 :)<br><BR>\"" fullword ascii /* PEStudio Blacklist: strings */
    $s8 = "<p>Serv-U Local Get SYSTEM Shell with ASP" fullword ascii /* PEStudio Blacklist: strings */
    $s9 = "\"-HomeDir=c:\\\\\" & vbcrlf & \"-LoginMesFile=\" & vbcrlf & \"-Disable=0\" & vb" ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 17KB and 2 of them
}