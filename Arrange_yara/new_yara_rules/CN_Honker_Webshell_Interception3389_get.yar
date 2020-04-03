rule CN_Honker_Webshell_Interception3389_get {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file get.asp"
    family = "None"
    hacker = "None"
    hash = "ceb6306f6379c2c1634b5058e1894b43abcf0296"
    judge = "unknown"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "userip = Request.ServerVariables(\"HTTP_X_FORWARDED_FOR\")" fullword ascii /* PEStudio Blacklist: strings */
    $s1 = "file.writeline  szTime + \" HostName:\" + szhostname + \" IP:\" + userip+\":\"+n" ascii /* PEStudio Blacklist: strings */
    $s3 = "set file=fs.OpenTextFile(server.MapPath(\"WinlogonHack.txt\"),8,True)" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 3KB and all of them
}