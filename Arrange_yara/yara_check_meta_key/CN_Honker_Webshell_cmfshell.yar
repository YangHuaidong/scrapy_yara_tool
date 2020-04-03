rule CN_Honker_Webshell_cmfshell {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file cmfshell.cmf"
    family = "None"
    hacker = "None"
    hash = "b9b2107c946431e4ad1a8f5e53ac05e132935c0e"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<cfexecute name=\"C:\\Winnt\\System32\\cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "<form action=\"<cfoutput>#CGI.SCRIPT_NAME#</cfoutput>\" method=\"post\">" fullword ascii /* PEStudio Blacklist: strings */
  condition:
    filesize < 4KB and all of them
}