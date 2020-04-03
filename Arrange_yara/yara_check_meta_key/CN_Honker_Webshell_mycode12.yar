rule CN_Honker_Webshell_mycode12 {
  meta:
    author = "Spider"
    comment = "None"
    date = "2015-06-23"
    description = "Webshell from CN Honker Pentest Toolset - file mycode12.cfm"
    family = "None"
    hacker = "None"
    hash = "64be8760be5ab5c2dcf829e3f87d3e50b1922f17"
    judge = "black"
    license = "https://creativecommons.org/licenses/by-nc/4.0/"
    reference = "Disclosed CN Honker Pentest Toolset"
    score = 70
    threatname = "None"
    threattype = "None"
  strings:
    $s1 = "<cfexecute name=\"cmd.exe\"" fullword ascii /* PEStudio Blacklist: strings */
    $s2 = "<cfoutput>#cmd#</cfoutput>" fullword ascii
  condition:
    filesize < 4KB and all of them
}