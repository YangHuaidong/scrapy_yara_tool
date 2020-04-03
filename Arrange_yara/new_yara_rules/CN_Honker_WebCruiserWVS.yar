rule CN_Honker_WebCruiserWVS {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file WebCruiserWVS.exe"
    family = "None"
    hacker = "None"
    hash = "6c90a9ed4c8a141a343dab1b115cc840a7190304"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "id:uid:user:username:password:access:account:accounts:admin_id:admin_name:admin_" ascii /* PEStudio Blacklist: strings */
    $s1 = "Created By WebCruiser - Web Vulnerability Scanner http://sec4app.com" fullword wide /* PEStudio Blacklist: strings */
  condition:
    uint16(0) == 0x5a4d and filesize < 700KB and all of them
}