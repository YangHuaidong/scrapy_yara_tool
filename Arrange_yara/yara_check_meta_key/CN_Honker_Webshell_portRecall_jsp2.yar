rule CN_Honker_Webshell_portRecall_jsp2 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file jsp2.txt"
    family = "None"
    hacker = "None"
    hash = "412ed15eb0d24298ba41731502018800ffc24bfc"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s0 = "final String remoteIP =request.getParameter(\"remoteIP\");" fullword ascii /* PEStudio Blacklist: strings */
    $s4 = "final String localIP = request.getParameter(\"localIP\");" fullword ascii /* PEStudio Blacklist: strings */
    $s20 = "final String localPort = \"3390\";//request.getParameter(\"localPort\");" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 23KB and all of them
}