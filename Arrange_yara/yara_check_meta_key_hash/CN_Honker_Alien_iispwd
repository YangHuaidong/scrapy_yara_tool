rule CN_Honker_Alien_iispwd {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Sample from CN Honker Pentest Toolset - file iispwd.vbs"
    family = "None"
    hacker = "None"
    hash = "5d157a1b9644adbe0b28c37d4022d88a9f58cedb"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "set IIs=objservice.GetObject(\"IIsWebServer\",childObjectName)" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "wscript.echo \"from : http://www.xxx.com/\" &vbTab&vbCrLf" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 3KB and all of them
}