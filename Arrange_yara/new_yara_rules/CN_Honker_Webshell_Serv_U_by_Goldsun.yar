rule CN_Honker_Webshell_Serv_U_by_Goldsun {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file Serv-U_by_Goldsun.asp"
    family = "None"
    hacker = "None"
    hash = "d4d7a632af65a961a1dbd0cff80d5a5c2b397e8c"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "b.open \"GET\", \"http://127.0.0.1:\" & ftpport & \"/goldsun/upadmin/s2\", True," ascii /* PEStudio Blacklist: strings */
    $s2 = "newuser = \"-SETUSERSETUP\" & vbCrLf & \"-IP=0.0.0.0\" & vbCrLf & \"-PortNo=\" &" ascii /* PEStudio Blacklist: strings */
    $s3 = "127.0.0.1:<%=port%>," fullword ascii /* PEStudio Blacklist: strings */
    $s4 = "GName=\"http://\" & request.servervariables(\"server_name\")&\":\"&request.serve" ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 30KB and 2 of them
}